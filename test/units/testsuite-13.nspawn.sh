#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

export SYSTEMD_LOG_LEVEL=debug
export SYSTEMD_LOG_TARGET=journal

at_exit() {
    set +e

    mountpoint -q /var/lib/machines && umount /var/lib/machines
}

trap at_exit EXIT

# check cgroup-v2
IS_CGROUPSV2_SUPPORTED=no
mkdir -p /tmp/cgroup2
if mount -t cgroup2 cgroup2 /tmp/cgroup2; then
    IS_CGROUPSV2_SUPPORTED=yes
    umount /tmp/cgroup2
fi
rmdir /tmp/cgroup2

# check cgroup namespaces
IS_CGNS_SUPPORTED=no
if [[ -f /proc/1/ns/cgroup ]]; then
    IS_CGNS_SUPPORTED=yes
fi

IS_USERNS_SUPPORTED=no
# On some systems (e.g. CentOS 7) the default limit for user namespaces
# is set to 0, which causes the following unshare syscall to fail, even
# with enabled user namespaces support. By setting this value explicitly
# we can ensure the user namespaces support to be detected correctly.
sysctl -w user.max_user_namespaces=10000
if unshare -U bash -c :; then
    IS_USERNS_SUPPORTED=yes
fi

# Mount tmpfs over /var/lib/machines to not pollute the image
mkdir -p /var/lib/machines
mount -t tmpfs tmpfs /var/lib/machines

testcase_sanity() {
    local template root image uuid tmpdir

    tmpdir="$(mktemp -d)"
    template="$(mktemp -d /tmp/nspawn-template.XXX)"
    create_dummy_container "$template"
    # Create a simple image from the just created container template
    image="$(mktemp /var/lib/machines/testsuite-13.image-XXX.img)"
    dd if=/dev/zero of="$image" bs=1M count=32
    mkfs.ext4 "$image"
    mkdir -p /mnt
    mount -o loop "$image" /mnt
    cp -r "$template"/* /mnt/
    umount /mnt

    systemd-nspawn --help --no-pager
    systemd-nspawn --version

    # --template=
    root="$(mktemp -u -d /var/lib/machines/testsuite-13.sanity.XXX)"
    (! systemd-nspawn --directory="$root" bash -xec 'echo hello')
    # Initialize $root from $template (the $root directory must not exist, hence
    # the `mktemp -u` above)
    systemd-nspawn --directory="$root" --template="$template" bash -xec 'echo hello'
    systemd-nspawn --directory="$root" bash -xec 'echo hello; touch /initialized'
    test -e "$root/initialized"
    # Check if the $root doesn't get re-initialized once it's not empty
    systemd-nspawn --directory="$root" --template="$template" bash -xec 'echo hello'
    test -e "$root/initialized"

    systemd-nspawn --directory="$root" --ephemeral bash -xec 'touch /ephemeral'
    test ! -e "$root/ephemeral"
    (! systemd-nspawn --directory="$root" \
                      --bind="${COVERAGE_BUILD_DIR:-$tmpdir}" \
                      --read-only \
                      bash -xec 'touch /nope')
    test ! -e "$root/nope"
    systemd-nspawn --image="$image" bash -xec 'echo hello'

    # --volatile=
    touch "$root/usr/has-usr"
    # volatile(=yes): rootfs is tmpfs, /usr/ from the OS tree is mounted read only
    systemd-nspawn --directory="$root"\
                   --volatile \
                   bash -xec 'test -e /usr/has-usr; touch /usr/read-only && exit 1; touch /nope'
    test ! -e "$root/nope"
    test ! -e "$root/usr/read-only"
    systemd-nspawn --directory="$root"\
                   --volatile=yes \
                   bash -xec 'test -e /usr/has-usr; touch /usr/read-only && exit 1; touch /nope'
    test ! -e "$root/nope"
    test ! -e "$root/usr/read-only"
    # volatile=state: rootfs is read-only, /var/ is tmpfs
    systemd-nspawn --directory="$root" \
                   --bind="${COVERAGE_BUILD_DIR:-$tmpdir}" \
                   --volatile=state \
                   bash -xec 'test -e /usr/has-usr; mountpoint /var; touch /read-only && exit 1; touch /var/nope'
    test ! -e "$root/read-only"
    test ! -e "$root/var/nope"
    # volatile=state: tmpfs overlay is mounted over rootfs
    systemd-nspawn --directory="$root" \
                   --volatile=overlay \
                   bash -xec 'test -e /usr/has-usr; touch /nope; touch /var/also-nope; touch /usr/nope-too'
    test ! -e "$root/nope"
    test ! -e "$root/var/also-nope"
    test ! -e "$root/usr/nope-too"

    # --machine=, --hostname=
    systemd-nspawn --directory="$root" \
                   --machine="foo-bar.baz" \
                   bash -xec '[[ $(hostname) == foo-bar.baz ]]'
    systemd-nspawn --directory="$root" \
                   --hostname="hello.world.tld" \
                   bash -xec '[[ $(hostname) == hello.world.tld ]]'
    systemd-nspawn --directory="$root" \
                   --machine="foo-bar.baz" \
                   --hostname="hello.world.tld" \
                   bash -xec '[[ $(hostname) == hello.world.tld ]]'

    # --uuid=
    rm -f "$root/etc/machine-id"
    uuid="deadbeef-dead-dead-beef-000000000000"
    systemd-nspawn --directory="$root" \
                   --uuid="$uuid" \
                   bash -xec "[[ \$container_uuid == $uuid ]]"

    # --as-pid2
    systemd-nspawn --directory="$root" bash -xec '[[ $$ -eq 1 ]]'
    systemd-nspawn --directory="$root" --as-pid2 bash -xec '[[ $$ -eq 2 ]]'

    # --user=
    # "Fake" getent passwd's bare minimum, so we don't have to pull it in
    # with all the DSO shenanigans
    cat >"$root/bin/getent" <<\EOF
#!/bin/bash

if [[ $# -eq 0 ]]; then
    :
elif [[ $1 == passwd ]]; then
    echo "testuser:x:1000:1000:testuser:/:/bin/sh"
elif [[ $1 == initgroups ]]; then
    echo "testuser"
fi
EOF
    chmod +x "$root/bin/getent"
    systemd-nspawn --directory="$root" bash -xec '[[ $USER == root ]]'
    systemd-nspawn --directory="$root" --user=testuser bash -xec '[[ $USER == testuser ]]'

    # --settings= + .nspawn files
    mkdir -p /run/systemd/nspawn/
    uuid="deadbeef-dead-dead-beef-000000000000"
    echo -ne "[Exec]\nMachineID=deadbeef-dead-dead-beef-111111111111" >/run/systemd/nspawn/foo-bar.nspawn
    systemd-nspawn --directory="$root" \
                   --machine=foo-bar \
                   --settings=yes \
                   bash -xec '[[ $container_uuid == deadbeef-dead-dead-beef-111111111111 ]]'
    systemd-nspawn --directory="$root" \
                   --machine=foo-bar \
                   --uuid="$uuid" \
                   --settings=yes \
                   bash -xec "[[ \$container_uuid == $uuid ]]"
    systemd-nspawn --directory="$root" \
                   --machine=foo-bar \
                   --uuid="$uuid" \
                   --settings=override \
                   bash -xec '[[ $container_uuid == deadbeef-dead-dead-beef-111111111111 ]]'
    systemd-nspawn --directory="$root" \
                   --machine=foo-bar \
                   --uuid="$uuid" \
                   --settings=trusted \
                   bash -xec "[[ \$container_uuid == $uuid ]]"

    # Mounts
    mkdir "$tmpdir"/{1,2,3}
    touch "$tmpdir/1/one" "$tmpdir/2/two" "$tmpdir/3/three"
    touch "$tmpdir/foo"
    # --bind=
    systemd-nspawn --directory="$root" \
                   --bind="$tmpdir:/foo" \
                   bash -xec 'test -e /foo/foo; touch /foo/bar'
    test -e "$tmpdir/bar"
    # --bind-ro=
    systemd-nspawn --directory="$root" \
                   --bind-ro="$tmpdir:/foo" \
                   bash -xec 'test -e /foo/foo; touch /foo/baz && exit 1; true'
    # --inaccessible=
    systemd-nspawn --directory="$root" \
                   --inaccessible=/var \
                   bash -xec 'touch /var/foo && exit 1; true'
    # --tmpfs=
    systemd-nspawn --directory="$root" \
                   --tmpfs=/var:rw,nosuid,noexec \
                   bash -xec 'touch /var/nope'
    test ! -e "$root/var/nope"
    # --overlay=
    systemd-nspawn --directory="$root" \
                   --overlay="$tmpdir/1:$tmpdir/2:$tmpdir/3:/var" \
                   bash -xec 'test -e /var/one; test -e /var/two; test -e /var/three; touch /var/foo'
    test -e "$tmpdir/3/foo"
    # --overlay-ro=
    systemd-nspawn --directory="$root" \
                   --overlay-ro="$tmpdir/1:$tmpdir/2:$tmpdir/3:/var" \
                   bash -xec 'test -e /var/one; test -e /var/two; test -e /var/three; touch /var/nope && exit 1; true'
    test ! -e "$tmpdir/3/nope"
    rm -fr "$tmpdir"

    # --port (sanity only)
    systemd-nspawn --network-veth --directory="$root" --port=80 --port=90 true
    systemd-nspawn --network-veth --directory="$root" --port=80:8080 true
    systemd-nspawn --network-veth --directory="$root" --port=tcp:80 true
    systemd-nspawn --network-veth --directory="$root" --port=tcp:80:8080 true
    systemd-nspawn --network-veth --directory="$root" --port=udp:80 true
    systemd-nspawn --network-veth --directory="$root" --port=udp:80:8080 --port=tcp:80:8080 true
    (! systemd-nspawn --network-veth --directory="$root" --port= true)
    (! systemd-nspawn --network-veth --directory="$root" --port=-1 true)
    (! systemd-nspawn --network-veth --directory="$root" --port=: true)
    (! systemd-nspawn --network-veth --directory="$root" --port=icmp:80:8080 true)
    (! systemd-nspawn --network-veth --directory="$root" --port=tcp::8080 true)
    (! systemd-nspawn --network-veth --directory="$root" --port=8080: true)

    # Assorted tests
    systemd-nspawn --directory="$root" --suppress-sync=yes bash -xec 'echo hello'
    systemd-nspawn --capability=help
    systemd-nspawn --resolv-conf=help
    systemd-nspawn --timezone=help

    # Handling of invalid arguments
    opts=(
        bind
        bind-ro
        bind-user
        chdir
        console
        inaccessible
        kill-signal
        link-journal
        load-credential
        network-{interface,macvlan,ipvlan,veth-extra,bridge,zone}
        no-new-privileges
        oom-score-adjust
        overlay
        overlay-ro
        personality
        pivot-root
        port
        private-users
        private-users-ownership
        register
        resolv-conf
        rlimit
        root-hash
        root-hash-sig
        set-credential
        settings
        suppress-sync
        timezone
        tmpfs
        uuid
    )
    for opt in "${opts[@]}"; do
        (! systemd-nspawn "--$opt")
        [[ "$opt" == network-zone ]] && continue
        (! systemd-nspawn "--$opt=''")
        (! systemd-nspawn "--$opt=%\$š")
    done
    (! systemd-nspawn --volatile="")
    (! systemd-nspawn --volatile=-1)
    (! systemd-nspawn --rlimit==)
}

testcase_bind_tmp_path() {
    # https://github.com/systemd/systemd/issues/4789
    local root

    root="$(mktemp -d /var/lib/machines/testsuite-13.bind-tmp-path.XXX)"
    create_dummy_container "$root"
    : >/tmp/bind
    systemd-nspawn --register=no \
                   --directory="$root" \
                   --bind=/tmp/bind \
                   bash -c 'test -e /tmp/bind'

    rm -fr "$root" /tmp/bind
}

testcase_norbind() {
    # https://github.com/systemd/systemd/issues/13170
    local root

    root="$(mktemp -d /var/lib/machines/testsuite-13.norbind-path.XXX)"
    mkdir -p /tmp/binddir/subdir
    echo -n "outer" >/tmp/binddir/subdir/file
    mount -t tmpfs tmpfs /tmp/binddir/subdir
    echo -n "inner" >/tmp/binddir/subdir/file
    create_dummy_container "$root"

    systemd-nspawn --register=no \
                   --directory="$root" \
                   --bind=/tmp/binddir:/mnt:norbind \
                   bash -c 'CONTENT=$(cat /mnt/subdir/file); if [[ $CONTENT != "outer" ]]; then echo "*** unexpected content: $CONTENT"; exit 1; fi'

    umount /tmp/binddir/subdir
    rm -fr "$root" /tmp/binddir/
}

rootidmap_cleanup() {
    local dir="${1:?}"

    mountpoint -q "$dir/bind" && umount "$dir/bind"
    rm -fr "$dir"
}

testcase_rootidmap() {
    local root cmd permissions
    local owner=1000

    root="$(mktemp -d /var/lib/machines/testsuite-13.rootidmap-path.XXX)"
    # Create ext4 image, as ext4 supports idmapped-mounts.
    mkdir -p /tmp/rootidmap/bind
    dd if=/dev/zero of=/tmp/rootidmap/ext4.img bs=4k count=2048
    mkfs.ext4 /tmp/rootidmap/ext4.img
    mount /tmp/rootidmap/ext4.img /tmp/rootidmap/bind
    trap "rootidmap_cleanup /tmp/rootidmap/" RETURN

    touch /tmp/rootidmap/bind/file
    chown -R "$owner:$owner" /tmp/rootidmap/bind

    create_dummy_container "$root"
    cmd='PERMISSIONS=$(stat -c "%u:%g" /mnt/file); if [[ $PERMISSIONS != "0:0" ]]; then echo "*** wrong permissions: $PERMISSIONS"; return 1; fi; touch /mnt/other_file'
    if ! SYSTEMD_LOG_TARGET=console \
            systemd-nspawn --register=no \
                           --directory="$root" \
                           --bind=/tmp/rootidmap/bind:/mnt:rootidmap \
                           bash -c "$cmd" |& tee nspawn.out; then
        if grep -q "Failed to map ids for bind mount.*: Function not implemented" nspawn.out; then
            echo "idmapped mounts are not supported, skipping the test..."
            return 0
        fi

        return 1
    fi

    permissions=$(stat -c "%u:%g" /tmp/rootidmap/bind/other_file)
    if [[ $permissions != "$owner:$owner" ]]; then
        echo "*** wrong permissions: $permissions"
        [[ "$IS_USERNS_SUPPORTED" == "yes" ]] && return 1
    fi
}

testcase_notification_socket() {
    # https://github.com/systemd/systemd/issues/4944
    local root
    local cmd='echo a | nc -U -u -w 1 /run/host/notify'

    root="$(mktemp -d /var/lib/machines/testsuite-13.check_notification_socket.XXX)"
    create_dummy_container "$root"

    systemd-nspawn --register=no --directory="$root" bash -x -c "$cmd"
    systemd-nspawn --register=no --directory="$root" -U bash -x -c "$cmd"
}

testcase_os_release() {
    local root entrypoint os_release_source

    root="$(mktemp -d /var/lib/machines/testsuite-13.os-release.XXX)"
    create_dummy_container "$root"
    entrypoint="$root/entrypoint.sh"
    cat >"$entrypoint" <<\EOF
#!/usr/bin/bash -ex

. /tmp/os-release
[[ -n "${ID:-}" && "$ID" != "$container_host_id" ]] && exit 1
[[ -n "${VERSION_ID:-}" && "$VERSION_ID" != "$container_host_version_id" ]] && exit 1
[[ -n "${BUILD_ID:-}" && "$BUILD_ID" != "$container_host_build_id" ]] && exit 1
[[ -n "${VARIANT_ID:-}" && "$VARIANT_ID" != "$container_host_variant_id" ]] && exit 1

cd /tmp
(cd /run/host && md5sum os-release) | md5sum -c
EOF
    chmod +x "$entrypoint"

    os_release_source="/etc/os-release"
    if [[ ! -r "$os_release_source" ]]; then
        os_release_source="/usr/lib/os-release"
    elif [[ -L "$os_release_source" ]]; then
        # Ensure that /etc always wins if available
        cp --remove-destination -fv /usr/lib/os-release /etc/os-release
        echo MARKER=1 >>/etc/os-release
    fi

    systemd-nspawn --register=no \
                   --directory="$root" \
                   --bind="$os_release_source:/tmp/os-release" \
                   "${entrypoint##"$root"}"

    if grep -q MARKER /etc/os-release; then
        ln -svrf /usr/lib/os-release /etc/os-release
    fi

    rm -fr "$root"
}

testcase_machinectl_bind() {
    local service_path service_name root container_name ec
    local cmd='for i in $(seq 1 20); do if test -f /tmp/marker; then exit 0; fi; sleep .5; done; exit 1;'

    root="$(mktemp -d /var/lib/machines/testsuite-13.machinectl-bind.XXX)"
    create_dummy_container "$root"
    container_name="$(basename "$root")"

    service_path="$(mktemp /run/systemd/system/nspawn-machinectl-bind-XXX.service)"
    service_name="${service_path##*/}"
    cat >"$service_path" <<EOF
[Service]
Type=notify
ExecStart=systemd-nspawn --directory="$root" --notify-ready=no /usr/bin/bash -xec "$cmd"
EOF

    systemctl daemon-reload
    systemctl start "$service_name"
    touch /tmp/marker
    machinectl bind --mkdir "$container_name" /tmp/marker

    timeout 10 bash -c "while [[ '\$(systemctl show -P SubState $service_name)' == running ]]; do sleep .2; done"
    ec="$(systemctl show -P ExecMainStatus "$service_name")"
    systemctl stop "$service_name"

    rm -fr "$root" "$service_path"

    return "$ec"
}

testcase_selinux() {
    # Basic test coverage to avoid issues like https://github.com/systemd/systemd/issues/19976
    if ! command -v selinuxenabled >/dev/null || ! selinuxenabled; then
        echo >&2 "SELinux is not enabled, skipping SELinux-related tests"
        return 0
    fi

    local root

    root="$(mktemp -d /var/lib/machines/testsuite-13.selinux.XXX)"
    create_dummy_container "$root"
    chcon -R -t container_t "$root"

    systemd-nspawn --register=no \
                   --boot \
                   --directory="$root" \
                   --selinux-apifs-context=system_u:object_r:container_file_t:s0:c0,c1 \
                   --selinux-context=system_u:system_r:container_t:s0:c0,c1

    rm -fr "$root"
}

testcase_ephemeral_config() {
    # https://github.com/systemd/systemd/issues/13297
    local root container_name

    root="$(mktemp -d /var/lib/machines/testsuite-13.ephemeral-config.XXX)"
    create_dummy_container "$root"
    container_name="$(basename "$root")"

    mkdir -p /run/systemd/nspawn/
    cat >"/run/systemd/nspawn/$container_name.nspawn" <<EOF
[Files]
BindReadOnly=/tmp/ephemeral-config
EOF
    touch /tmp/ephemeral-config

    systemd-nspawn --register=no \
                   --directory="$root" \
                   --ephemeral \
                   bash -x -c "test -f /tmp/ephemeral-config"

    systemd-nspawn --register=no \
                   --directory="$root" \
                   --ephemeral \
                   --machine=foobar \
                   bash -x -c "! test -f /tmp/ephemeral-config"

    rm -fr "$root" "/run/systemd/nspawn/$container_name"
}

matrix_run_one() {
    local cgroupsv2="${1:?}"
    local use_cgns="${2:?}"
    local api_vfs_writable="${3:?}"
    local root

    if [[ "$cgroupsv2" == "yes" && "$IS_CGROUPSV2_SUPPORTED" == "no" ]]; then
        echo >&2 "Unified cgroup hierarchy is not supported, skipping..."
        return 0
    fi

    if [[ "$use_cgns" == "yes" && "$IS_CGNS_SUPPORTED" == "no" ]];  then
        echo >&2 "CGroup namespaces are not supported, skipping..."
        return 0
    fi

    root="$(mktemp -d "/var/lib/machines/testsuite-13.unified-$1-cgns-$2-api-vfs-writable-$3.XXX")"
    create_dummy_container "$root"

    SYSTEMD_NSPAWN_UNIFIED_HIERARCHY="$cgroupsv2" SYSTEMD_NSPAWN_USE_CGNS="$use_cgns" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$api_vfs_writable" \
        systemd-nspawn --register=no \
                       --directory="$root" \
                       --boot

    SYSTEMD_NSPAWN_UNIFIED_HIERARCHY="$cgroupsv2" SYSTEMD_NSPAWN_USE_CGNS="$use_cgns" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$api_vfs_writable" \
        systemd-nspawn --register=no \
                       --directory="$root" \
                       --private-network \
                       --boot

    if SYSTEMD_NSPAWN_UNIFIED_HIERARCHY="$cgroupsv2" SYSTEMD_NSPAWN_USE_CGNS="$use_cgns" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$api_vfs_writable" \
        systemd-nspawn --register=no \
                       --directory="$root" \
                       --private-users=pick \
                       --boot; then
        [[ "$IS_USERNS_SUPPORTED" == "yes" && "$api_vfs_writable" == "network" ]] && return 1
    else
        [[ "$IS_USERNS_SUPPORTED" == "no" && "$api_vfs_writable" = "network" ]] && return 1
    fi

    if SYSTEMD_NSPAWN_UNIFIED_HIERARCHY="$cgroupsv2" SYSTEMD_NSPAWN_USE_CGNS="$use_cgns" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$api_vfs_writable" \
        systemd-nspawn --register=no \
                       --directory="$root" \
                       --private-network \
                       --private-users=pick \
                       --boot; then
        [[ "$IS_USERNS_SUPPORTED" == "yes" && "$api_vfs_writable" == "yes" ]] && return 1
    else
        [[ "$IS_USERNS_SUPPORTED" == "no" && "$api_vfs_writable" = "yes" ]] && return 1
    fi

    local netns_opt="--network-namespace-path=/proc/self/ns/net"
    local net_opt
    local net_opts=(
        "--network-bridge=lo"
        "--network-interface=lo"
        "--network-ipvlan=lo"
        "--network-macvlan=lo"
        "--network-veth"
        "--network-veth-extra=lo"
        "--network-zone=zone"
    )

    # --network-namespace-path and network-related options cannot be used together
    for net_opt in "${net_opts[@]}"; do
        echo "$netns_opt in combination with $net_opt should fail"
        if SYSTEMD_NSPAWN_UNIFIED_HIERARCHY="$cgroupsv2" SYSTEMD_NSPAWN_USE_CGNS="$use_cgns" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$api_vfs_writable" \
            systemd-nspawn --register=no \
                           --directory="$root" \
                           --boot \
                           "$netns_opt" \
                           "$net_opt"; then
            echo >&2 "unexpected pass"
            return 1
        fi
    done

    # allow combination of --network-namespace-path and --private-network
    SYSTEMD_NSPAWN_UNIFIED_HIERARCHY="$cgroupsv2" SYSTEMD_NSPAWN_USE_CGNS="$use_cgns" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$api_vfs_writable" \
        systemd-nspawn --register=no \
                       --directory="$root" \
                       --boot \
                       --private-network \
                       "$netns_opt"

    # test --network-namespace-path works with a network namespace created by "ip netns"
    ip netns add nspawn_test
    netns_opt="--network-namespace-path=/run/netns/nspawn_test"
    SYSTEMD_NSPAWN_UNIFIED_HIERARCHY="$cgroupsv2" SYSTEMD_NSPAWN_USE_CGNS="$use_cgns" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$api_vfs_writable" \
        systemd-nspawn --register=no \
                       --directory="$root" \
                       --network-namespace-path=/run/netns/nspawn_test \
                       ip a | grep -v -E '^1: lo.*UP'
    ip netns del nspawn_test

    rm -fr "$root"

    return 0
}

# Create a list of all functions prefixed with testcase_
mapfile -t TESTCASES < <(declare -F | awk '$3 ~ /^testcase_/ {print $3;}')

if [[ "${#TESTCASES[@]}" -eq 0 ]]; then
    echo >&2 "No test cases found, this is most likely an error"
    exit 1
fi

for testcase in "${TESTCASES[@]}"; do
    "$testcase"
done

for api_vfs_writable in yes no network; do
    matrix_run_one no  no  $api_vfs_writable
    matrix_run_one yes no  $api_vfs_writable
    matrix_run_one no  yes $api_vfs_writable
    matrix_run_one yes yes $api_vfs_writable
done
