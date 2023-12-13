/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "json.h"
#include "missing_magic.h"
#include "path-util.h"
#include "rm-rf.h"
#include "user-util.h"
#include "userns-registry.h"

int userns_registry_open_fd(void) {
        int fd;

        fd = open_mkdirp_at(AT_FDCWD, "/run/systemd/nsresource/registry", O_CLOEXEC|O_NOFOLLOW, 0755);
        if (fd < 0)
                return log_debug_errno(fd, "Failed to open registry dir: %m");

        return fd;
}

int userns_registry_lock(int dir_fd) {
        _cleanup_close_ int registry_fd = -EBADF, lock_fd = -EBADF;

        if (dir_fd < 0) {
                registry_fd = userns_registry_open_fd();
                if (registry_fd < 0)
                        return registry_fd;

                dir_fd = registry_fd;
        }

        lock_fd = xopenat_lock(dir_fd, "lock", O_CREAT|O_RDWR|O_CLOEXEC, /* xopen_flags= */ 0, 0600, LOCK_BSD, LOCK_EX);
        if (lock_fd < 0)
                return log_debug_errno(lock_fd, "Failed to open nsresource registry lock file: %m");

        return TAKE_FD(lock_fd);
}

UserNamespaceInfo* userns_info_new(void) {

        UserNamespaceInfo *info = new(UserNamespaceInfo, 1);
        if (!info)
                return NULL;

        *info = (UserNamespaceInfo) {
                .owner = UID_INVALID,
                .start = UID_INVALID,
                .target = UID_INVALID,
        };

        return info;
}

UserNamespaceInfo *userns_info_free(UserNamespaceInfo *userns) {
        if (!userns)
                return NULL;

        free(userns->cgroups);
        free(userns->name);

        return mfree(userns);
}

static int dispatch_cgroups_array(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        UserNamespaceInfo *info = ASSERT_PTR(userdata);
        _cleanup_free_ uint64_t *cgroups = NULL;
        size_t n_cgroups = 0;

        if (json_variant_is_null(variant)) {
                info->cgroups = mfree(info->cgroups);
                info->n_cgroups = 0;
                return 0;
        }

        if (!json_variant_is_array(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not an array.", strna(name));

        cgroups = new(uint64_t, json_variant_elements(variant));
        if (!cgroups)
                return json_log_oom(variant, flags);

        JsonVariant *e;
        JSON_VARIANT_ARRAY_FOREACH(e, variant) {
                bool found = false;

                if (!json_variant_is_unsigned(e))
                        return json_log(e, flags, SYNTHETIC_ERRNO(EINVAL), "JSON array element is not a number.");

                for (size_t j = 0; j < n_cgroups; j++)
                        if (cgroups[j] == json_variant_unsigned(e)) {
                                found = true;
                                break;
                        }
                if (found) /* suppress duplicate */
                        continue;

                cgroups[n_cgroups++] = json_variant_unsigned(e);
        }

        assert(n_cgroups <= json_variant_elements(variant));

        free_and_replace(info->cgroups, cgroups);
        info->n_cgroups = n_cgroups;

        return 0;
}

static int userns_registry_load(int dir_fd, const char *fn, UserNamespaceInfo **ret) {

        static const JsonDispatch dispatch_table[] = {
                { "owner",   JSON_VARIANT_UNSIGNED, json_dispatch_uid_gid,  offsetof(UserNamespaceInfo, owner),        JSON_MANDATORY },
                { "name",    JSON_VARIANT_STRING,   json_dispatch_string,   offsetof(UserNamespaceInfo, name),         JSON_MANDATORY },
                { "userns",  JSON_VARIANT_UNSIGNED, json_dispatch_uint64,   offsetof(UserNamespaceInfo, userns_inode), JSON_MANDATORY },
                { "start",   JSON_VARIANT_UNSIGNED, json_dispatch_uid_gid,  offsetof(UserNamespaceInfo, start),        0              },
                { "size",    JSON_VARIANT_UNSIGNED, json_dispatch_uint32,   offsetof(UserNamespaceInfo, size),         0              },
                { "target",  JSON_VARIANT_UNSIGNED, json_dispatch_uid_gid,  offsetof(UserNamespaceInfo, target),       0              },
                { "cgroups", JSON_VARIANT_ARRAY,    dispatch_cgroups_array, 0,                                         0              },
                {}
        };

        _cleanup_(userns_info_freep) UserNamespaceInfo *userns_info = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_close_ int registry_fd = -EBADF;
        int r;

        if (dir_fd < 0) {
                registry_fd = userns_registry_open_fd();
                if (registry_fd < 0)
                        return registry_fd;

                dir_fd = registry_fd;
        }

        r = json_parse_file_at(NULL, dir_fd, fn, 0, &v, NULL, NULL);
        if (r < 0)
                return r;

        userns_info = userns_info_new();
        if (!userns_info)
                return -ENOMEM;

        r = json_dispatch(v, dispatch_table, 0, userns_info);
        if (r < 0)
                return r;

        if (userns_info->userns_inode == 0)
                return -EBADMSG;
        if (userns_info->start == 0)
                return -EBADMSG;
        if (userns_info->size == 0) {
                if (uid_is_valid(userns_info->start) || uid_is_valid(userns_info->target))
                        return -EBADMSG;
        } else {
                if (!uid_is_valid(userns_info->start) || !uid_is_valid(userns_info->target))
                        return -EBADMSG;

                if (userns_info->size > UINT32_MAX - userns_info->start ||
                    userns_info->size > UINT32_MAX - userns_info->target)
                        return -EBADMSG;
        }

        if (ret)
                *ret = TAKE_PTR(userns_info);
        return 0;
}

int userns_registry_uid_exists(int dir_fd, uid_t start) {
        _cleanup_free_ char *fn = NULL;

        assert(dir_fd >= 0);

        if (!uid_is_valid(start))
                return -ENOENT;

        if (start == 0)
                return true;

        if (asprintf(&fn, "u" UID_FMT ".userns", start) < 0)
                return -ENOMEM;

        if (faccessat(dir_fd, fn, F_OK, AT_SYMLINK_NOFOLLOW) < 0)
                return errno == ENOENT ? false : -errno;

        return true;
}

int userns_registry_name_exists(int dir_fd, const char *name) {
        _cleanup_free_ char *fn = NULL;

        assert(dir_fd >= 0);

        if (!userns_name_is_valid(name))
                return -EINVAL;

        fn = strjoin("n", name, ".userns");
        if (!fn)
                return -ENOMEM;

        if (faccessat(dir_fd, fn, F_OK, AT_SYMLINK_NOFOLLOW) < 0)
                return errno == ENOENT ? false : -errno;

        return true;
}

int userns_registry_inode_exists(int dir_fd, uint64_t inode) {
        _cleanup_free_ char *fn = NULL;

        assert(dir_fd >= 0);

        if (inode <= 0)
                return -EINVAL;

        if (asprintf(&fn, "i%" PRIu64 ".userns", inode) < 0)
                return -ENOMEM;

        if (faccessat(dir_fd, fn, F_OK, AT_SYMLINK_NOFOLLOW) < 0)
                return errno == ENOENT ? false : -errno;

        return true;
}

int userns_registry_load_by_start_uid(int dir_fd, uid_t start, UserNamespaceInfo **ret) {
        _cleanup_(userns_info_freep) UserNamespaceInfo *userns_info = NULL;
        _cleanup_free_ char *fn = NULL;
        int r;

        assert(dir_fd >= 0);

        if (!uid_is_valid(start))
                return -ENOENT;

        if (asprintf(&fn, "u" UID_FMT ".userns", start) < 0)
                return -ENOMEM;

        r = userns_registry_load(dir_fd, fn, &userns_info);
        if (r < 0)
                return r;

        if (userns_info->start != start)
                return -EBADMSG;

        if (ret)
                *ret = TAKE_PTR(userns_info);

        return 0;
}

int userns_registry_load_by_userns_inode(int dir_fd, uint64_t inode, UserNamespaceInfo **ret) {
        _cleanup_(userns_info_freep) UserNamespaceInfo *userns_info = NULL;
        _cleanup_free_ char *fn = NULL;
        int r;

        if (inode == 0)
                return -ENOENT;

        if (asprintf(&fn, "i%" PRIu64 ".userns", inode) < 0)
                return -ENOMEM;

        r = userns_registry_load(dir_fd, fn, &userns_info);
        if (r < 0)
                return r;

        if (userns_info->userns_inode != inode)
                return -EBADMSG;

        if (ret)
                *ret = TAKE_PTR(userns_info);

        return 0;
}

int userns_registry_store(int dir_fd, UserNamespaceInfo *info) {
        _cleanup_close_ int registry_fd = -EBADF;
        int r;

        assert(info);

        if (!uid_is_valid(info->owner) ||
            !info->name ||
            info->userns_inode == 0)
                return -EINVAL;

        if (dir_fd < 0) {
                registry_fd = userns_registry_open_fd();
                if (registry_fd < 0)
                        return registry_fd;

                dir_fd = registry_fd;
        }

        log_notice("alive 1.1");

        _cleanup_(json_variant_unrefp) JsonVariant *cgroup_array = NULL;
        for (size_t i = 0; i < info->n_cgroups; i++) {
                r = json_variant_append_arrayb(
                                &cgroup_array,
                                JSON_BUILD_UNSIGNED(info->cgroups[i]));
                if (r < 0)
                        return r;
        }

        log_notice("alive 1.2");

        _cleanup_(json_variant_unrefp) JsonVariant *def = NULL;
        r = json_build(&def, JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("owner", JSON_BUILD_UNSIGNED(info->owner)),
                                       JSON_BUILD_PAIR("name", JSON_BUILD_STRING(info->name)),
                                       JSON_BUILD_PAIR("userns", JSON_BUILD_UNSIGNED(info->userns_inode)),
                                       JSON_BUILD_PAIR_CONDITION(uid_is_valid(info->start), "start", JSON_BUILD_UNSIGNED(info->start)),
                                       JSON_BUILD_PAIR_CONDITION(uid_is_valid(info->start), "size", JSON_BUILD_UNSIGNED(info->size)),
                                       JSON_BUILD_PAIR_CONDITION(uid_is_valid(info->start), "target", JSON_BUILD_UNSIGNED(info->target)),
                                       JSON_BUILD_PAIR_CONDITION(cgroup_array, "cgroups", JSON_BUILD_VARIANT(cgroup_array))));
        if (r < 0)
                return r;

        _cleanup_free_ char *def_buf = NULL;
        r = json_variant_format(def, 0, &def_buf);
        if (r < 0)
                return log_debug_errno(r, "Failed to format userns JSON object: %m");

        _cleanup_free_ char *reg_fn = NULL, *link1_fn = NULL, *link2_fn = NULL;
        if (asprintf(&reg_fn, "i%" PRIu64 ".userns", info->userns_inode) < 0)
                return log_oom_debug();

        r = write_string_file_at(dir_fd, reg_fn, def_buf, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC);
        if (r < 0)
                return log_error_errno(r, "Failed to write userns data to '%s' in registry: %m", reg_fn);

        link1_fn = strjoin("n", info->name, ".userns");
        if (!link1_fn) {
                r = log_oom_debug();
                goto fail;
        }

        r = linkat_replace(dir_fd, reg_fn, dir_fd, link1_fn);
        if (r < 0) {
                log_error_errno(r, "Failed to link userns data to to '%s' in registry: %m", link1_fn);
                goto fail;
        }

        if (uid_is_valid(info->start)) {
                if (asprintf(&link2_fn, "u" UID_FMT ".userns", info->start) < 0) {
                        r = log_oom_debug();
                        goto fail;
                }

                r = linkat_replace(dir_fd, reg_fn, dir_fd, link2_fn);
                if (r < 0) {
                        log_error_errno(r, "Failed to link userns data to to '%s' in registry: %m", link2_fn);
                        goto fail;
                }
        }

        return 0;

fail:
        if (reg_fn)
                (void) unlinkat(dir_fd, reg_fn, /* flags= */ 0);
        if (link1_fn)
                (void) unlinkat(dir_fd, link1_fn, /* flags= */ 0);
        if (link2_fn)
                (void) unlinkat(dir_fd, link2_fn, /* flags= */ 0);

        return r;
}

int userns_registry_remove(int dir_fd, UserNamespaceInfo *info) {
        _cleanup_close_ int registry_fd = -EBADF;
        int ret = 0;

        assert(info);

        if (dir_fd < 0) {
                registry_fd = userns_registry_open_fd();
                if (registry_fd < 0)
                        return registry_fd;

                dir_fd = registry_fd;
        }

        _cleanup_free_ char *reg_fn = NULL;
        if (asprintf(&reg_fn, "i%" PRIu64 ".userns", info->userns_inode) < 0)
                return log_oom_debug();

        ret = RET_NERRNO(unlinkat(dir_fd, reg_fn, 0));

        _cleanup_free_ char *link1_fn = NULL;
        link1_fn = strjoin("n", info->name, ".userns");
        if (!link1_fn)
                return log_oom_debug();

        RET_GATHER(ret, RET_NERRNO(unlinkat(dir_fd, link1_fn, 0)));

        if (uid_is_valid(info->start)) {
                _cleanup_free_ char *link2_fn = NULL;

                if (asprintf(&link2_fn, "u" UID_FMT ".userns", info->start) < 0)
                        return log_oom_debug();

                RET_GATHER(ret, RET_NERRNO(unlinkat(dir_fd, link2_fn, 0)));
        }

        return ret;
}

bool userns_info_has_cgroup(UserNamespaceInfo *userns, uint64_t cgroup_id) {
        assert(userns);

        FOREACH_ARRAY(i, userns->cgroups, userns->n_cgroups)
                if (*i == cgroup_id)
                        return true;

        return false;
}

int userns_info_add_cgroup(UserNamespaceInfo *userns, uint64_t cgroup_id) {

        if (userns_info_has_cgroup(userns, cgroup_id))
                return 0;

        if (!GREEDY_REALLOC(userns->cgroups, userns->n_cgroups+1))
                return -ENOMEM;

        userns->cgroups[userns->n_cgroups++] = cgroup_id;
        return 1;
}

static int userns_destroy_cgroup(uint64_t cgroup_id) {
        _cleanup_close_ int cgroup_fd = -EBADF, parent_fd = -EBADF;
        int r;

        log_notice("trying to remove cgroup %" PRIu64, cgroup_id);

        cgroup_fd = cg_cgroupid_open(/* cgroupfsfd= */ -EBADF, cgroup_id);
        if (cgroup_fd == -ESTALE) {
                log_debug_errno(cgroup_fd, "Control group %" PRIu64 " already gone, ignoring: %m", cgroup_id);
                return 0;
        }
        if (cgroup_fd < 0)
                return log_warning_errno(errno, "Failed to open cgroup %" PRIu64 ", ignoring: %m", cgroup_id);

        _cleanup_free_ char *path = NULL;
        r = fd_get_path(cgroup_fd, &path);
        if (r < 0)
                return log_error_errno(r, "Failed to get path of cgroup %" PRIu64 ", ignoring: %m", cgroup_id);

        const char *e = path_startswith(path, "/sys/fs/cgroup/");
        if (!e)
                return log_error_errno(SYNTHETIC_ERRNO(EPERM), "Got cgroup path that doesn't start with /sys/fs/cgroup/, refusing: %s", path);
        if (isempty(e))
                return log_error_errno(SYNTHETIC_ERRNO(EPERM), "Got root cgroup path, which can't be right, refusing.");

        log_debug("Path of cgroup %" PRIu64 " is: %s", cgroup_id, path);

        _cleanup_free_ char *fname = NULL;
        r = path_extract_filename(path, &fname);
        if (r < 0)
                return log_error_errno(r, "Failed to extract name of cgroup %" PRIu64 ", ignoring: %m", cgroup_id);

        parent_fd = openat(cgroup_fd, "..", O_CLOEXEC|O_DIRECTORY);
        if (parent_fd < 0)
                return log_error_errno(errno, "Failed to open parent cgroup of %" PRIu64 ", ignoring: %m", cgroup_id);

        /* Safety check, never leave cgroupfs */
        r = fd_is_fs_type(parent_fd, CGROUP2_SUPER_MAGIC);
        if (r < 0)
                return log_error_errno(r, "Failed to determine if parent directory of cgroup %" PRIu64 " is still a cgroup, ignoring: %m", cgroup_id);
        if (!r)
                return log_error_errno(SYNTHETIC_ERRNO(EPERM), "Parent directory of cgroup %" PRIu64 " is not a cgroup, refusing.", cgroup_id);

        cgroup_fd = safe_close(cgroup_fd);

        r = rm_rf_child(parent_fd, fname, REMOVE_ONLY_DIRECTORIES|REMOVE_PHYSICAL|REMOVE_CHMOD);
        if (r < 0)
                log_warning_errno(r, "Failed to remove delegated cgroup %" PRIu64 ", ignoring: %m", cgroup_id);

        return 0;
}

int userns_info_remove_cgroups(UserNamespaceInfo *userns) {
        int ret = 0;

        assert(userns);

        log_notice("removing cgroups of %s", strna(userns->name));

        FOREACH_ARRAY(c, userns->cgroups, userns->n_cgroups)
                RET_GATHER(ret, userns_destroy_cgroup(*c));

        userns->cgroups = mfree(userns->cgroups);
        userns->n_cgroups = 0;

        return ret;
}

bool userns_name_is_valid(const char *name) {

        /* Checks if the specified string is suitable as user namespace name. */

        if (strlen(name) > NAME_MAX) /* before we use alloca(), let's check for size */
                return false;

        const char *f = strjoina("n", name); /* Make sure we can name our lookup symlink with this name */
        if (!filename_is_valid(f))
                return false;

        const char *u = strjoina("ns_", name, "65535"); /* Make sure we can turn this into valid user names */
        if (!valid_user_group_name(u, 0))
                return false;

        return true;
}
