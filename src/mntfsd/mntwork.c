/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-daemon.h"

#include "argv-util.h"
#include "dissect-image.h"
#include "env-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "main-func.h"
#include "missing_loop.h"
#include "namespace-util.h"
#include "process-util.h"
#include "stat-util.h"
#include "user-util.h"
#include "varlink.h"

/* When we use F_GETFL to get file flags, this will likely contain O_LARGEFILE set, but glibc defines that to
 * 0 if we are compiling in _LARGEFILE64_SOURCE mode on archs that by default have a 32bit off_t. Let's hence
 * define our own macro for this, in this case */
#if O_LARGEFILE != 0
#define RAW_O_LARGEFILE O_LARGEFILE
#else
#define RAW_O_LARGEFILE 0100000
#endif

#define ITERATIONS_MAX 64U
#define RUNTIME_MAX_USEC (5 * USEC_PER_MINUTE)
#define PRESSURE_SLEEP_TIME_USEC (50 * USEC_PER_MSEC)
#define CONNECTION_IDLE_USEC (15 * USEC_PER_SEC)
#define LISTEN_IDLE_USEC (90 * USEC_PER_SEC)

typedef struct MountImageParameters {
        unsigned image_fd_idx;
        unsigned userns_fd_idx;
        int read_only;
        int growfs;
        char *password;
} MountImageParameters;

static void mount_image_parameters_done(MountImageParameters *p) {
        assert(p);
        erase_and_free(p->password);
}

static unsigned max_idx(unsigned a, unsigned b) {
        if (a == UINT_MAX)
                return b;
        if (b == UINT_MAX)
                return a;

        return MAX(a, b);
}

static int verify_safe_fd(int fd, MountImageParameters *p) {
        int r, fl;

        assert(fd >= 0);
        assert(p);

        r = fd_verify_regular(fd);
        if (r < 0)
                return r;

        fl = fcntl(fd, F_GETFL);
        if (fl < 0)
                return -errno;

        switch (fl & O_ACCMODE) {

        case O_RDONLY:
                p->read_only = true;
                break;

        case O_RDWR:
                break;

        default:
                return -EBADF;
        }

        /* Refuse fds with unexpected flags. In paticular we don't want to allow O_PATH fds, since with those
         * it's not guarantee the client actually has access to the file */
        if ((fl & ~(O_ACCMODE|RAW_O_LARGEFILE)) != 0)
                return -EBADF;

        return 0;
}

static int vl_method_mount_image(
                Varlink *link,
                JsonVariant *parameters,
                VarlinkMethodFlags flags,
                void *userdata) {

        static const JsonDispatch dispatch_table[] = {
                { "imageFileDescriptor",         JSON_VARIANT_UNSIGNED, json_dispatch_uint,     offsetof(MountImageParameters, image_fd_idx),  JSON_MANDATORY },
                { "userNamespaceFileDescriptor", JSON_VARIANT_UNSIGNED, json_dispatch_uint,     offsetof(MountImageParameters, userns_fd_idx), 0 },
                { "readOnly",                    JSON_VARIANT_BOOLEAN,  json_dispatch_tristate, offsetof(MountImageParameters, read_only),     0 },
                { "growFileSystems",             JSON_VARIANT_BOOLEAN,  json_dispatch_tristate, offsetof(MountImageParameters, growfs),        0 },
                { "password",                    JSON_VARIANT_STRING,   json_dispatch_string,   offsetof(MountImageParameters, password),      0 },
                {}
        };


        _cleanup_(verity_settings_done) VeritySettings verity = VERITY_SETTINGS_DEFAULT;
        _cleanup_(mount_image_parameters_done) MountImageParameters p = {
                .image_fd_idx = UINT_MAX,
                .userns_fd_idx = UINT_MAX,
                .read_only = -1,
                .growfs = -1,
        };
        _cleanup_(dissected_image_unrefp) DissectedImage *di = NULL;
        _cleanup_(loop_device_unrefp) LoopDevice *loop = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *aj = NULL;
        _cleanup_close_ int image_fd = -EBADF, userns_fd = -EBADF;
        size_t m;
        int r;

        assert(link);
        assert(parameters);

        json_variant_sensitive(parameters); /* might contain passwords */

        r = json_dispatch(parameters, dispatch_table, NULL, 0, &p);
        if (r < 0)
                return r;

        if (p.image_fd_idx != UINT_MAX) {
                image_fd = varlink_take_fd(link, p.image_fd_idx);
                if (image_fd < 0)
                        return image_fd;
        }

        if (p.userns_fd_idx != UINT_MAX) {
                userns_fd = varlink_take_fd(link, p.userns_fd_idx);
                if (userns_fd < 0)
                        return userns_fd;
        }

        m = max_idx(p.image_fd_idx, p.userns_fd_idx);
        if (m != UINT_MAX) {
                r = varlink_drop_fd(link, m + 1);
                if (r < 0)
                        return r;
        }

        r = verify_safe_fd(image_fd, &p);
        if (r < 0)
                return r;

        if (userns_fd >= 0) {
                r = fd_is_ns(userns_fd, CLONE_NEWUSER);
                if (r < 0)
                        return r;
                if (r == 0)
                        return varlink_error(link, "io.systemd.MountFileSystem.UserNamespaceInvalid", NULL);
        }

        DissectImageFlags dissect_flags =
                (p.read_only == 0 ? DISSECT_IMAGE_READ_ONLY : 0) |
                DISSECT_IMAGE_DISCARD_ANY |
                (p.growfs != 0 ? DISSECT_IMAGE_GROWFS : 0) |
                DISSECT_IMAGE_FSCK |
                DISSECT_IMAGE_ADD_PARTITION_DEVICES |
                DISSECT_IMAGE_PIN_PARTITION_DEVICES;

        r = loop_device_make(
                        image_fd,
                        p.read_only == 0 ? O_RDONLY : O_RDWR,
                        0,
                        UINT64_MAX,
                        UINT32_MAX,
                        LO_FLAGS_PARTSCAN,
                        LOCK_EX,
                        &loop);
        if (r < 0)
                return r;

        r = dissect_loop_device(
                        loop,
                        &verity,
                        /* mount_options= */ NULL,
                        dissect_flags,
                        &di);
        if (r < 0)
                return r;

        r = dissected_image_load_verity_sig_partition(
                        di,
                        loop->fd,
                        &verity);
        if (r < 0)
                return r;

        r = dissected_image_decrypt(
                        di,
                        p.password,
                        &verity,
                        dissect_flags);
        if (r < 0)
                return r;

        r = dissected_image_mount(
                        di,
                        /* where= */ NULL,
                        /* uid_shift= */ UID_INVALID,
                        /* uid_range= */ UID_INVALID,
                        userns_fd,
                        dissect_flags);
        if (r < 0)
                return r;

        for (PartitionDesignator d = 0; d < _PARTITION_DESIGNATOR_MAX; d++) {
                _cleanup_(json_variant_unrefp) JsonVariant *pj = NULL;
                int fd_idx;

                if (!di->partitions[d].found)
                        continue;

                if (di->partitions[d].fsmount_fd < 0)
                        continue;

                fd_idx = varlink_push_fd(link, di->partitions[d].fsmount_fd);
                if (fd_idx < 0)
                        return fd_idx;

                TAKE_FD(di->partitions[d].fsmount_fd);

                r = json_build(&pj,
                               JSON_BUILD_OBJECT(
                                               JSON_BUILD_PAIR("designator", JSON_BUILD_STRING(partition_designator_to_string(d))),
                                               JSON_BUILD_PAIR("mountFileDescriptor", JSON_BUILD_INTEGER(fd_idx))));
                if (r < 0)
                        return r;

                r = json_variant_append_array(&aj, pj);
                if (r < 0)
                        return r;
        }

        r = varlink_replyb(link, JSON_BUILD_OBJECT(
                                              JSON_BUILD_PAIR("partitions", JSON_BUILD_VARIANT(aj))));
        if (r < 0)
                return r;

        loop_device_relinquish(loop);
        return r;
}

static int process_connection(VarlinkServer *server, int _fd) {
        _cleanup_close_ int fd = TAKE_FD(_fd); /* always take possesion */
        _cleanup_(varlink_close_unrefp) Varlink *vl = NULL;
        int r;

        r = varlink_server_add_connection(server, fd, &vl);
        if (r < 0)
                return log_error_errno(r, "Failed to add connection: %m");

        TAKE_FD(fd);
        vl = varlink_ref(vl);

        r = varlink_set_allow_fd_passing_input(vl, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable fd passing for read: %m");

        r = varlink_set_allow_fd_passing_output(vl, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable fd passing for write: %m");

        for (;;) {
                r = varlink_process(vl);
                if (r == -ENOTCONN) {
                        log_debug("Connection terminated.");
                        break;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to process connection: %m");
                if (r > 0)
                        continue;

                r = varlink_wait(vl, CONNECTION_IDLE_USEC);
                if (r < 0)
                        return log_error_errno(r, "Failed to wait for connection events: %m");
                if (r == 0)
                        break;
        }

        return 0;
}

static int run(int argc, char *argv[]) {
        usec_t start_time, listen_idle_usec, last_busy_usec = USEC_INFINITY;
        _cleanup_(varlink_server_unrefp) VarlinkServer *server = NULL;
        unsigned n_iterations = 0;
        int m, listen_fd, r;

        log_setup();

        m = sd_listen_fds(false);
        if (m < 0)
                return log_error_errno(m, "Failed to determine number of listening fds: %m");
        if (m == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No socket to listen on received.");
        if (m > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Worker can only listen on a single socket at a time.");

        listen_fd = SD_LISTEN_FDS_START;

        r = fd_nonblock(listen_fd, false);
        if (r < 0)
                return log_error_errno(r, "Failed to turn off non-blocking mode for listening socket: %m");

        r = varlink_server_new(&server, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate server: %m");

        r = varlink_server_bind_method_many(
                        server,
                        "io.systemd.MountFileSystem.MountImage",  vl_method_mount_image);
        if (r < 0)
                return log_error_errno(r, "Failed to bind methods: %m");

        r = getenv_bool("MNTFS_FIXED_WORKER");
        if (r < 0)
                return log_error_errno(r, "Failed to parse MNTFSD_FIXED_WORKER: %m");
        listen_idle_usec = r ? USEC_INFINITY : LISTEN_IDLE_USEC;

        start_time = now(CLOCK_MONOTONIC);

        for (;;) {
                _cleanup_close_ int fd = -EBADF;
                usec_t n;

                /* Exit the worker in regular intervals, to flush out all memory use */
                if (n_iterations++ > ITERATIONS_MAX) {
                        log_debug("Exiting worker, processed %u iterations, that's enough.", n_iterations);
                        break;
                }

                n = now(CLOCK_MONOTONIC);
                if (n >= usec_add(start_time, RUNTIME_MAX_USEC)) {
                        log_debug("Exiting worker, ran for %s, that's enough.",
                                  FORMAT_TIMESPAN(usec_sub_unsigned(n, start_time), 0));
                        break;
                }

                if (last_busy_usec == USEC_INFINITY)
                        last_busy_usec = n;
                else if (listen_idle_usec != USEC_INFINITY && n >= usec_add(last_busy_usec, listen_idle_usec)) {
                        log_debug("Exiting worker, been idle for %s.",
                                  FORMAT_TIMESPAN(usec_sub_unsigned(n, last_busy_usec), 0));
                        break;
                }

                (void) rename_process("systemd-mntwork: waiting...");
                fd = RET_NERRNO(accept4(listen_fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC));
                (void) rename_process("systemd-mntwork: processing...");

                if (fd == -EAGAIN)
                        continue; /* The listening socket has SO_RECVTIMEO set, hence a timeout is expected
                                   * after a while, let's check if it's time to exit though. */
                if (fd == -EINTR)
                        continue; /* Might be that somebody attached via strace, let's just continue in that
                                   * case */
                if (fd < 0)
                        return log_error_errno(fd, "Failed to accept() from listening socket: %m");

                if (now(CLOCK_MONOTONIC) <= usec_add(n, PRESSURE_SLEEP_TIME_USEC)) {
                        /* We only slept a very short time? If so, let's see if there are more sockets
                         * pending, and if so, let's ask our parent for more workers */

                        r = fd_wait_for_event(listen_fd, POLLIN, 0);
                        if (r < 0)
                                return log_error_errno(r, "Failed to test for POLLIN on listening socket: %m");

                        if (FLAGS_SET(r, POLLIN)) {
                                pid_t parent;

                                parent = getppid();
                                if (parent <= 1)
                                        return log_error_errno(SYNTHETIC_ERRNO(ESRCH), "Parent already died?");

                                if (kill(parent, SIGUSR2) < 0)
                                        return log_error_errno(errno, "Failed to kill our own parent: %m");
                        }
                }

                (void) process_connection(server, TAKE_FD(fd));
                last_busy_usec = USEC_INFINITY;
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
