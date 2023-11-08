#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="cryptsetup systemd setup"
IMAGE_NAME="cryptsetup"
IMAGE_ADDITIONAL_DATA_SIZE=100
TEST_NO_NSPAWN=1
TEST_FORCE_NEWIMAGE=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_require_bin softhsm2-util pkcs11-tool certtool

PART_UUID="deadbeef-dead-dead-beef-000000000000"
DM_NAME="test24_varcrypt"
KERNEL_OPTIONS=(
    "rd.luks=1"
    "luks.name=$PART_UUID=$DM_NAME"
    "luks.key=$PART_UUID=/keyfile:LABEL=varcrypt_keydev"
    "luks.options=$PART_UUID=x-initrd.attach"
)
KERNEL_APPEND+=" ${KERNEL_OPTIONS[*]}"
QEMU_OPTIONS+=" -drive format=raw,cache=unsafe,file=${STATEDIR:?}/keydev.img"

check_result_qemu() {
    local ret

    mount_initdir

    cryptsetup luksOpen "${LOOPDEV:?}p2" "${DM_NAME:?}" <"$TESTDIR/keyfile"
    mount "/dev/mapper/$DM_NAME" "$initdir/var"

    check_result_common "${initdir:?}" && ret=0 || ret=$?

    _umount_dir "$initdir/var"
    _umount_dir "$initdir"
    cryptsetup luksClose "/dev/mapper/$DM_NAME"

    return $ret
}

setup_pkcs11_token() {
    local P11_MODULE_CONFIGS_DIR P11_MODULE_DIR SOFTHSM_MODULE

    export SOFTHSM2_CONF="/tmp/softhsm2.conf"
    mkdir -p "$initdir/var/lib/softhsm/tokens/"
    cat >> ${SOFTHSM2_CONF} <<EOF
directories.tokendir = $initdir/var/lib/softhsm/tokens/
objectstore.backend = file
slots.removable = false
slots.mechanisms = ALL
EOF
    export GNUTLS_PIN="1234"
    export GNUTLS_SO_PIN="12345678"
    softhsm2-util --init-token --free --label "TestToken" --pin ${GNUTLS_PIN} --so-pin ${GNUTLS_SO_PIN}

    if ! P11_MODULE_CONFIGS_DIR=$(pkg-config --variable=p11_module_configs p11-kit-1); then
        echo "WARNING! Cannot get p11_module_configs from p11-kit-1.pc, assuming /usr/share/p11-kit/modules" >&2
        P11_MODULE_CONFIGS_DIR="/usr/share/p11-kit/modules"
    fi

    if ! P11_MODULE_DIR=$(pkg-config --variable=p11_module_path p11-kit-1); then
        echo "WARNING! Cannot get p11_module_path from p11-kit-1.pc, assuming /usr/lib/pkcs11" >&2
        P11_MODULE_DIR="/usr/lib/pkcs11"
    fi

    SOFTHSM_MODULE=$(grep -F 'module:' "$P11_MODULE_CONFIGS_DIR/softhsm2.module"| cut -d ':' -f 2| xargs)
    if [[ "$SOFTHSM_MODULE" =~ ^[^/] ]]; then
        SOFTHSM_MODULE="$P11_MODULE_DIR/$SOFTHSM_MODULE"
    fi

    # RSA #####################################################
    pkcs11-tool --module "$SOFTHSM_MODULE" --token-label "TestToken" --pin "env:GNUTLS_PIN" --so-pin "env:GNUTLS_SO_PIN" --keypairgen --key-type "RSA:2048" --label "RSATestKey" --usage-decrypt

    certtool --generate-self-signed \
      --load-privkey="pkcs11:token=TestToken;object=RSATestKey;type=private" \
      --load-pubkey="pkcs11:token=TestToken;object=RSATestKey;type=public" \
      --template "$TEST_BASE_DIR/$TESTNAME/template.cfg" \
      --outder --outfile "/tmp/rsa_test.crt"

    pkcs11-tool --module "$SOFTHSM_MODULE" --token-label "TestToken" --pin "env:GNUTLS_PIN" --so-pin "env:GNUTLS_SO_PIN" --write-object "/tmp/rsa_test.crt" --type cert --label "RSATestKey"
    rm "/tmp/rsa_test.crt"

    # prime256v1 ##############################################
    pkcs11-tool --module "$SOFTHSM_MODULE" --token-label "TestToken" --pin "env:GNUTLS_PIN" --so-pin "env:GNUTLS_SO_PIN" --keypairgen --key-type "EC:prime256v1" --label "ECTestKey" --usage-derive

    certtool --generate-self-signed \
      --load-privkey="pkcs11:token=TestToken;object=ECTestKey;type=private" \
      --load-pubkey="pkcs11:token=TestToken;object=ECTestKey;type=public" \
      --template "$TEST_BASE_DIR/$TESTNAME/template.cfg" \
      --outder --outfile "/tmp/ec_test.crt"

    pkcs11-tool --module "$SOFTHSM_MODULE" --token-label "TestToken" --pin "env:GNUTLS_PIN" --so-pin "env:GNUTLS_SO_PIN" --write-object "/tmp/ec_test.crt" --type cert --label "ECTestKey"
    rm "/tmp/ec_test.crt"

    ###########################################################
    rm ${SOFTHSM2_CONF}
    unset SOFTHSM2_CONF

    inst_libs "$SOFTHSM_MODULE"
    inst_library "$SOFTHSM_MODULE"
    inst_simple "$P11_MODULE_CONFIGS_DIR/softhsm2.module"

    cat >> "$initdir/etc/softhsm2.conf" <<EOF
directories.tokendir = /var/lib/softhsm/tokens/
objectstore.backend = file
slots.removable = false
slots.mechanisms = ALL
log.level = INFO
EOF

    mkdir -p "$initdir/etc/systemd/system/systemd-cryptsetup@.service.d"
    cat >> "$initdir/etc/systemd/system/systemd-cryptsetup@.service.d/PIN.conf" <<EOF
[Service]
Environment="PIN=$GNUTLS_PIN"
EOF

    unset GNUTLS_PIN
    unset GNUTLS_SO_PIN
}

test_create_image() {
    create_empty_image_rootdir

    echo -n test >"${TESTDIR:?}/keyfile"
    cryptsetup -q luksFormat --uuid="$PART_UUID" --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "${LOOPDEV:?}p2" "$TESTDIR/keyfile"
    cryptsetup luksOpen "${LOOPDEV}p2" "${DM_NAME:?}" <"$TESTDIR/keyfile"
    mkfs.ext4 -L var "/dev/mapper/$DM_NAME"
    mkdir -p "${initdir:?}/var"
    mount "/dev/mapper/$DM_NAME" "$initdir/var"

    LOG_LEVEL=5

    setup_basic_environment
    mask_supporting_services

    install_dmevent
    generate_module_dependencies

    setup_pkcs11_token

    # Create a keydev
    dd if=/dev/zero of="${STATEDIR:?}/keydev.img" bs=1M count=16
    mkfs.ext4 -L varcrypt_keydev "$STATEDIR/keydev.img"
    mkdir -p "$STATEDIR/keydev"
    mount "$STATEDIR/keydev.img" "$STATEDIR/keydev"
    echo -n test >"$STATEDIR/keydev/keyfile"
    sync "$STATEDIR/keydev"
    umount "$STATEDIR/keydev"

    cat >>"$initdir/etc/fstab" <<EOF
/dev/mapper/$DM_NAME    /var    ext4    defaults 0 1
EOF

    # Forward journal messages to the console, so we have something
    # to investigate even if we fail to mount the encrypted /var
    echo ForwardToConsole=yes >>"$initdir/etc/systemd/journald.conf"

    # If $INITRD wasn't provided explicitly, generate a custom one with dm-crypt
    # support
    if [[ -z "$INITRD" ]]; then
        INITRD="${TESTDIR:?}/initrd.img"
        dinfo "Generating a custom initrd with dm-crypt support in '${INITRD:?}'"

        if command -v dracut >/dev/null; then
            dracut --force --verbose --add crypt "$INITRD"
        elif command -v mkinitcpio >/dev/null; then
            mkinitcpio -S autodetect --addhooks sd-encrypt --generate "$INITRD"
        elif command -v mkinitramfs >/dev/null; then
            # The cryptroot hook is provided by the cryptsetup-initramfs package
            if ! dpkg-query -s cryptsetup-initramfs; then
                derror "Missing 'cryptsetup-initramfs' package for dm-crypt support in initrd"
                return 1
            fi

            mkinitramfs -o "$INITRD"
        else
            dfatal "Unrecognized initrd generator, can't continue"
            return 1
        fi
    fi
}

cleanup_root_var() {
    mountpoint -q "$initdir/var" && umount "$initdir/var"
    [[ -b "/dev/mapper/${DM_NAME:?}" ]] && cryptsetup luksClose "/dev/mapper/$DM_NAME"
    mountpoint -q "${STATEDIR:?}/keydev" && umount "$STATEDIR/keydev"
}

test_cleanup() {
    # ignore errors, so cleanup can continue
    cleanup_root_var || :
    _test_cleanup
}

test_setup_cleanup() {
    cleanup_root_var || :
    cleanup_initdir
}

do_test "$@"
