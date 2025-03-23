/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "cgroup-util.h"
#include "common-signal.h"
#include "daemon-util.h"
#include "device-monitor-private.h"
#include "device-private.h"
#include "device-util.h"
#include "errno-list.h"
#include "event-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "hashmap.h"
#include "iovec-util.h"
#include "list.h"
#include "mkdir.h"
#include "notify-recv.h"
#include "process-util.h"
#include "selinux-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "syslog-util.h"
#include "udev-builtin.h"
#include "udev-config.h"
#include "udev-ctrl.h"
#include "udev-error.h"
#include "udev-event.h"
#include "udev-manager.h"
#include "udev-manager-ctrl.h"
#include "udev-node.h"
#include "udev-rules.h"
#include "udev-spawn.h"
#include "udev-trace.h"
#include "udev-util.h"
#include "udev-varlink.h"
#include "udev-watch.h"
#include "udev-worker.h"

#define EVENT_RETRY_INTERVAL_USEC (200 * USEC_PER_MSEC)
#define EVENT_RETRY_TIMEOUT_USEC  (3 * USEC_PER_MINUTE)

typedef enum EventState {
        EVENT_UNDEF,
        EVENT_QUEUED,
        EVENT_RUNNING,
} EventState;

typedef struct Event {
        Manager *manager;
        Worker *worker;
        EventState state;

        sd_device *dev;

        sd_device_action_t action;
        uint64_t seqnum;
        uint64_t blocker_seqnum;
        const char *id;
        const char *devpath;
        const char *devpath_old;
        const char *devnode;

        /* Used when the device is locked by another program. */
        usec_t retry_again_next_usec;
        usec_t retry_again_timeout_usec;
        sd_event_source *retry_event_source;

        sd_event_source *timeout_warning_event;
        sd_event_source *timeout_event;

        LIST_FIELDS(Event, event);
} Event;

typedef enum WorkerState {
        WORKER_UNDEF,
        WORKER_RUNNING,
        WORKER_IDLE,
        WORKER_KILLED,
        WORKER_KILLING,
} WorkerState;

typedef struct Worker {
        Manager *manager;
        pid_t pid;
        sd_event_source *child_event_source;
        union sockaddr_union address;
        WorkerState state;
        Event *event;
} Worker;

static Event* event_free(Event *event) {
        if (!event)
                return NULL;

        assert(event->manager);

        LIST_REMOVE(event, event->manager->events, event);
        sd_device_unref(event->dev);

        sd_event_source_unref(event->retry_event_source);
        sd_event_source_unref(event->timeout_warning_event);
        sd_event_source_unref(event->timeout_event);

        if (event->worker)
                event->worker->event = NULL;

        return mfree(event);
}

static void event_queue_cleanup(Manager *manager, EventState match_state) {
        LIST_FOREACH(event, event, manager->events) {
                if (match_state != EVENT_UNDEF && match_state != event->state)
                        continue;

                event_free(event);
        }
}

static Worker* worker_free(Worker *worker) {
        if (!worker)
                return NULL;

        if (worker->manager)
                hashmap_remove(worker->manager->workers, PID_TO_PTR(worker->pid));

        sd_event_source_unref(worker->child_event_source);
        event_free(worker->event);

        return mfree(worker);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Worker*, worker_free);
DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                worker_hash_op,
                void,
                trivial_hash_func,
                trivial_compare_func,
                Worker,
                worker_free);

Manager* manager_free(Manager *manager) {
        if (!manager)
                return NULL;

        udev_builtin_exit();

        hashmap_free(manager->properties);
        udev_rules_free(manager->rules);

        hashmap_free(manager->workers);
        event_queue_cleanup(manager, EVENT_UNDEF);

        safe_close(manager->inotify_fd);
        hashmap_free(manager->inotify_device_ids_by_watch_handle);
        hashmap_free(manager->inotify_watch_handles_by_device_id);

        sd_device_monitor_unref(manager->monitor);
        udev_ctrl_unref(manager->ctrl);
        sd_varlink_server_unref(manager->varlink_server);

        sd_event_source_unref(manager->inotify_event);
        set_free(manager->synthesize_change_child_event_sources);
        sd_event_source_unref(manager->kill_workers_event);
        sd_event_unref(manager->event);

        free(manager->cgroup);
        return mfree(manager);
}

static int on_sigchld(sd_event_source *s, const siginfo_t *si, void *userdata);

static int worker_new(Worker **ret, Manager *manager, sd_device_monitor *worker_monitor, pid_t pid) {
        _cleanup_(worker_freep) Worker *worker = NULL;
        int r;

        assert(ret);
        assert(manager);
        assert(worker_monitor);
        assert(pid > 1);

        worker = new(Worker, 1);
        if (!worker)
                return -ENOMEM;

        *worker = (Worker) {
                .pid = pid,
        };

        r = device_monitor_get_address(worker_monitor, &worker->address);
        if (r < 0)
                return r;

        r = sd_event_add_child(manager->event, &worker->child_event_source, pid, WEXITED, on_sigchld, worker);
        if (r < 0)
                return r;

        r = hashmap_ensure_put(&manager->workers, &worker_hash_op, PID_TO_PTR(pid), worker);
        if (r < 0)
                return r;

        worker->manager = manager;

        *ret = TAKE_PTR(worker);
        return 0;
}

void manager_kill_workers(Manager *manager, bool force) {
        Worker *worker;

        assert(manager);

        HASHMAP_FOREACH(worker, manager->workers) {
                if (worker->state == WORKER_KILLED)
                        continue;

                if (worker->state == WORKER_RUNNING && !force) {
                        worker->state = WORKER_KILLING;
                        continue;
                }

                worker->state = WORKER_KILLED;
                (void) kill(worker->pid, SIGTERM);
        }
}

void manager_exit(Manager *manager) {
        assert(manager);

        manager->exit = true;

        (void) sd_notify(/* unset= */ false, NOTIFY_STOPPING);

        /* close sources of new events and discard buffered events */
        manager->ctrl = udev_ctrl_unref(manager->ctrl);
        manager->varlink_server = sd_varlink_server_unref(manager->varlink_server);

        /* Disable the event source, but do not close the fd. It will be pushed to fd store. */
        manager->inotify_event = sd_event_source_disable_unref(manager->inotify_event);

        /* Disable the device monitor but do not free device monitor, as it may be used when a worker failed,
         * and the manager needs to broadcast the kernel event assigned to the worker to libudev listeners.
         * Note, hwere we cannot use sd_device_monitor_stop(), as it changes the multicast group of the socket. */
        (void) sd_event_source_set_enabled(sd_device_monitor_get_event_source(manager->monitor), SD_EVENT_OFF);
        (void) sd_device_monitor_detach_event(manager->monitor);

        /* discard queued events and kill workers */
        event_queue_cleanup(manager, EVENT_QUEUED);
        manager_kill_workers(manager, true);
}

void notify_ready(Manager *manager) {
        int r;

        assert(manager);

        r = sd_notifyf(/* unset= */ false,
                       "READY=1\n"
                       "STATUS=Processing with %u children at max", manager->config.children_max);
        if (r < 0)
                log_warning_errno(r, "Failed to send readiness notification, ignoring: %m");
}

/* reload requested, HUP signal received, rules changed, builtin changed */
void manager_reload(Manager *manager, bool force) {
        _cleanup_(udev_rules_freep) UdevRules *rules = NULL;
        usec_t now_usec;
        int r;

        assert(manager);

        assert_se(sd_event_now(manager->event, CLOCK_MONOTONIC, &now_usec) >= 0);
        if (!force && now_usec < usec_add(manager->last_usec, 3 * USEC_PER_SEC))
                /* check for changed config, every 3 seconds at most */
                return;
        manager->last_usec = now_usec;

        /* Reload SELinux label database, to make the child inherit the up-to-date database. */
        mac_selinux_maybe_reload();

        UdevReloadFlags flags = udev_builtin_should_reload();
        if (udev_rules_should_reload(manager->rules))
                flags |= UDEV_RELOAD_RULES | UDEV_RELOAD_KILL_WORKERS;
        if (flags == 0 && !force)
                /* Neither .rules files nor config files for builtins e.g. .link files changed. It is not
                 * necessary to reload configs. Note, udev.conf is not checked in the above, hence reloaded
                 * when explicitly requested or at least one .rules file or friend is updated. */
                return;

        (void) notify_reloading();

        flags |= manager_reload_config(manager);

        if (FLAGS_SET(flags, UDEV_RELOAD_KILL_WORKERS))
                manager_kill_workers(manager, false);

        udev_builtin_reload(flags);

        if (FLAGS_SET(flags, UDEV_RELOAD_RULES)) {
                r = udev_rules_load(&rules, manager->config.resolve_name_timing, /* extra = */ NULL);
                if (r < 0)
                        log_warning_errno(r, "Failed to read udev rules, using the previously loaded rules, ignoring: %m");
                else
                        udev_rules_free_and_replace(manager->rules, rules);
        }

        notify_ready(manager);
}

static int on_kill_workers_event(sd_event_source *s, uint64_t usec, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);

        log_debug("Cleanup idle workers");
        manager_kill_workers(manager, false);

        return 1;
}

static int on_event_timeout(sd_event_source *s, uint64_t usec, void *userdata) {
        Event *event = ASSERT_PTR(userdata);

        assert(event->manager);
        assert(event->worker);

        kill_and_sigcont(event->worker->pid, event->manager->config.timeout_signal);
        event->worker->state = WORKER_KILLED;

        log_device_error(event->dev, "Worker ["PID_FMT"] processing SEQNUM=%"PRIu64" killed", event->worker->pid, event->seqnum);

        return 1;
}

static int on_event_timeout_warning(sd_event_source *s, uint64_t usec, void *userdata) {
        Event *event = ASSERT_PTR(userdata);

        assert(event->worker);

        log_device_warning(event->dev, "Worker ["PID_FMT"] processing SEQNUM=%"PRIu64" is taking a long time", event->worker->pid, event->seqnum);

        return 1;
}

static usec_t extra_timeout_usec(void) {
        static usec_t saved = 10 * USEC_PER_SEC;
        static bool parsed = false;
        usec_t timeout;
        const char *e;
        int r;

        if (parsed)
                return saved;

        parsed = true;

        e = getenv("SYSTEMD_UDEV_EXTRA_TIMEOUT_SEC");
        if (!e)
                return saved;

        r = parse_sec(e, &timeout);
        if (r < 0)
                log_debug_errno(r, "Failed to parse $SYSTEMD_UDEV_EXTRA_TIMEOUT_SEC=%s, ignoring: %m", e);

        if (timeout > 5 * USEC_PER_HOUR) /* Add an arbitrary upper bound */
                log_debug("Parsed $SYSTEMD_UDEV_EXTRA_TIMEOUT_SEC=%s is too large, ignoring.", e);
        else
                saved = timeout;

        return saved;
}

static void worker_attach_event(Worker *worker, Event *event) {
        Manager *manager = ASSERT_PTR(ASSERT_PTR(worker)->manager);
        sd_event *e = ASSERT_PTR(manager->event);

        assert(event);
        assert(!event->worker);
        assert(!worker->event);

        worker->state = WORKER_RUNNING;
        worker->event = event;
        event->state = EVENT_RUNNING;
        event->worker = worker;

        (void) sd_event_add_time_relative(e, &event->timeout_warning_event, CLOCK_MONOTONIC,
                                          udev_warn_timeout(manager->config.timeout_usec), USEC_PER_SEC,
                                          on_event_timeout_warning, event);

        /* Manager.timeout_usec is also used as the timeout for running programs specified in
         * IMPORT{program}=, PROGRAM=, or RUN=. Here, let's add an extra time before the manager
         * kills a worker, to make it possible that the worker detects timed out of spawned programs,
         * kills them, and finalizes the event. */
        (void) sd_event_add_time_relative(e, &event->timeout_event, CLOCK_MONOTONIC,
                                          usec_add(manager->config.timeout_usec, extra_timeout_usec()), USEC_PER_SEC,
                                          on_event_timeout, event);
}

static int worker_spawn(Manager *manager, Event *event) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *worker_monitor = NULL;
        Worker *worker;
        pid_t pid;
        int r;

        /* listen for new events */
        r = device_monitor_new_full(&worker_monitor, MONITOR_GROUP_NONE, -1);
        if (r < 0)
                return r;

        (void) sd_device_monitor_set_description(worker_monitor, "worker");

        /* allow the main daemon netlink address to send devices to the worker */
        r = device_monitor_allow_unicast_sender(worker_monitor, manager->monitor);
        if (r < 0)
                return log_error_errno(r, "Worker: Failed to set unicast sender: %m");

        r = safe_fork("(udev-worker)", FORK_DEATHSIG_SIGTERM, &pid);
        if (r < 0) {
                event->state = EVENT_QUEUED;
                return log_error_errno(r, "Failed to fork() worker: %m");
        }
        if (r == 0) {
                _cleanup_(udev_worker_done) UdevWorker w = {
                        .monitor = TAKE_PTR(worker_monitor),
                        .properties = TAKE_PTR(manager->properties),
                        .rules = TAKE_PTR(manager->rules),
                        .inotify_fd = TAKE_FD(manager->inotify_fd),
                        .config = manager->config,
                };

                if (setenv("NOTIFY_SOCKET", "/run/udev/notify", /* overwrite = */ true) < 0) {
                        log_error_errno(errno, "Failed to set $NOTIFY_SOCKET: %m");
                        _exit(EXIT_FAILURE);
                }

                /* Worker process */
                r = udev_worker_main(&w, event->dev);
                log_close();
                _exit(r < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
        }

        r = worker_new(&worker, manager, worker_monitor, pid);
        if (r < 0)
                return log_error_errno(r, "Failed to create worker object: %m");

        worker_attach_event(worker, event);

        log_device_debug(event->dev, "Worker ["PID_FMT"] is forked for processing SEQNUM=%"PRIu64".", pid, event->seqnum);
        return 0;
}

static int event_run(Event *event) {
        static bool log_children_max_reached = true;
        Manager *manager;
        Worker *worker;
        int r;

        assert(event);
        assert(event->manager);

        log_device_uevent(event->dev, "Device ready for processing");

        (void) event_source_disable(event->retry_event_source);

        manager = event->manager;
        HASHMAP_FOREACH(worker, manager->workers) {
                if (worker->state != WORKER_IDLE)
                        continue;

                r = device_monitor_send(manager->monitor, &worker->address, event->dev);
                if (r < 0) {
                        log_device_error_errno(event->dev, r, "Worker ["PID_FMT"] did not accept message, killing the worker: %m",
                                               worker->pid);
                        (void) kill(worker->pid, SIGKILL);
                        worker->state = WORKER_KILLED;
                        continue;
                }
                worker_attach_event(worker, event);
                return 1; /* event is now processing. */
        }

        if (hashmap_size(manager->workers) >= manager->config.children_max) {
                /* Avoid spamming the debug logs if the limit is already reached and
                 * many events still need to be processed */
                if (log_children_max_reached && manager->config.children_max > 1) {
                        log_debug("Maximum number (%u) of children reached.", hashmap_size(manager->workers));
                        log_children_max_reached = false;
                }
                return 0; /* no free worker */
        }

        /* Re-enable the debug message for the next batch of events */
        log_children_max_reached = true;

        /* start new worker and pass initial device */
        r = worker_spawn(manager, event);
        if (r < 0)
                return r;

        return 1; /* event is now processing. */
}

bool devpath_conflict(const char *a, const char *b) {
        /* This returns true when two paths are equivalent, or one is a child of another. */

        if (!a || !b)
                return false;

        for (; *a != '\0' && *b != '\0'; a++, b++)
                if (*a != *b)
                        return false;

        return *a == '/' || *b == '/' || *a == *b;
}

static int event_is_blocked(Event *event) {
        Event *loop_event = NULL;
        int r;

        /* lookup event for identical, parent, child device */

        assert(event);
        assert(event->manager);
        assert(event->blocker_seqnum <= event->seqnum);

        if (event->retry_again_next_usec > 0) {
                usec_t now_usec;

                r = sd_event_now(event->manager->event, CLOCK_BOOTTIME, &now_usec);
                if (r < 0)
                        return r;

                if (event->retry_again_next_usec > now_usec)
                        return true;
        }

        if (event->blocker_seqnum == event->seqnum)
                /* we have checked previously and no blocker found */
                return false;

        LIST_FOREACH(event, e, event->manager->events) {
                loop_event = e;

                /* we already found a later event, earlier cannot block us, no need to check again */
                if (loop_event->seqnum < event->blocker_seqnum)
                        continue;

                /* event we checked earlier still exists, no need to check again */
                if (loop_event->seqnum == event->blocker_seqnum)
                        return true;

                /* found ourself, no later event can block us */
                if (loop_event->seqnum >= event->seqnum)
                        goto no_blocker;

                /* found event we have not checked */
                break;
        }

        assert(loop_event);
        assert(loop_event->seqnum > event->blocker_seqnum &&
               loop_event->seqnum < event->seqnum);

        /* check if queue contains events we depend on */
        LIST_FOREACH(event, e, loop_event) {
                loop_event = e;

                /* found ourself, no later event can block us */
                if (loop_event->seqnum >= event->seqnum)
                        goto no_blocker;

                if (streq_ptr(loop_event->id, event->id))
                        break;

                if (devpath_conflict(event->devpath, loop_event->devpath) ||
                    devpath_conflict(event->devpath, loop_event->devpath_old) ||
                    devpath_conflict(event->devpath_old, loop_event->devpath))
                        break;

                if (event->devnode && streq_ptr(event->devnode, loop_event->devnode))
                        break;
        }

        assert(loop_event);

        log_device_debug(event->dev, "SEQNUM=%" PRIu64 " blocked by SEQNUM=%" PRIu64,
                         event->seqnum, loop_event->seqnum);

        event->blocker_seqnum = loop_event->seqnum;
        return true;

no_blocker:
        event->blocker_seqnum = event->seqnum;
        return false;
}

static int event_queue_start(Manager *manager) {
        int r;

        assert(manager);

        if (!manager->events || manager->exit || manager->stop_exec_queue)
                return 0;

        r = event_source_disable(manager->kill_workers_event);
        if (r < 0)
                log_warning_errno(r, "Failed to disable event source for cleaning up idle workers, ignoring: %m");

        manager_reload(manager, /* force = */ false);

        LIST_FOREACH(event, event, manager->events) {
                if (event->state != EVENT_QUEUED)
                        continue;

                /* do not start event if parent or child event is still running or queued */
                r = event_is_blocked(event);
                if (r > 0)
                        continue;
                if (r < 0)
                        log_device_warning_errno(event->dev, r,
                                                 "Failed to check dependencies for event (SEQNUM=%"PRIu64", ACTION=%s), "
                                                 "assuming there is no blocking event, ignoring: %m",
                                                 event->seqnum,
                                                 strna(device_action_to_string(event->action)));

                r = event_run(event);
                if (r <= 0) /* 0 means there are no idle workers. Let's escape from the loop. */
                        return r;
        }

        return 0;
}

static int on_event_retry(sd_event_source *s, uint64_t usec, void *userdata) {
        /* This does nothing. The on_post() callback will start the event if there exists an idle worker. */
        return 1;
}

static void event_requeue(Event *event) {
        usec_t now_usec;
        int r;

        assert(event);
        assert(event->manager);
        assert(event->manager->event);

        sd_device *dev = ASSERT_PTR(event->dev);

        event->timeout_warning_event = sd_event_source_disable_unref(event->timeout_warning_event);
        event->timeout_event = sd_event_source_disable_unref(event->timeout_event);

        /* add a short delay to suppress busy loop */
        r = sd_event_now(event->manager->event, CLOCK_BOOTTIME, &now_usec);
        if (r < 0) {
                log_device_warning_errno(
                                dev, r,
                                "Failed to get current time, skipping event (SEQNUM=%"PRIu64", ACTION=%s): %m",
                                event->seqnum, strna(device_action_to_string(event->action)));
                goto fail;
        }

        if (event->retry_again_timeout_usec > 0 && event->retry_again_timeout_usec <= now_usec) {
                r = log_device_warning_errno(
                                dev, SYNTHETIC_ERRNO(ETIMEDOUT),
                                "The underlying block device is locked by a process more than %s, skipping event (SEQNUM=%"PRIu64", ACTION=%s).",
                                FORMAT_TIMESPAN(EVENT_RETRY_TIMEOUT_USEC, USEC_PER_MINUTE),
                                event->seqnum, strna(device_action_to_string(event->action)));
                goto fail;
        }

        event->retry_again_next_usec = usec_add(now_usec, EVENT_RETRY_INTERVAL_USEC);
        if (event->retry_again_timeout_usec == 0)
                event->retry_again_timeout_usec = usec_add(now_usec, EVENT_RETRY_TIMEOUT_USEC);

        r = event_reset_time_relative(event->manager->event, &event->retry_event_source,
                                      CLOCK_MONOTONIC, EVENT_RETRY_INTERVAL_USEC, 0,
                                      on_event_retry, NULL,
                                      0, "retry-event", true);
        if (r < 0) {
                log_device_warning_errno(
                                dev, r,
                                "Failed to reset timer event source for retrying event, skipping event (SEQNUM=%"PRIu64", ACTION=%s): %m",
                                event->seqnum, strna(device_action_to_string(event->action)));
                goto fail;
        }

        if (event->worker)
                event->worker->event = NULL;
        event->worker = NULL;

        event->state = EVENT_QUEUED;
        return;

fail:
        (void) device_add_errno(dev, r);
        r = device_monitor_send(event->manager->monitor, NULL, dev);
        if (r < 0)
                log_device_warning_errno(dev, r, "Failed to broadcast event to libudev listeners, ignoring: %m");

        event_free(event);
}

int event_queue_assume_block_device_unlocked(Manager *manager, sd_device *dev) {
        const char *devname;
        int r;

        /* When a new event for a block device is queued or we get an inotify event, assume that the
         * device is not locked anymore. The assumption may not be true, but that should not cause any
         * issues, as in that case events will be requeued soon. */

        r = udev_get_whole_disk(dev, NULL, &devname);
        if (r <= 0)
                return r;

        LIST_FOREACH(event, event, manager->events) {
                const char *event_devname;

                if (event->state != EVENT_QUEUED)
                        continue;

                if (event->retry_again_next_usec == 0)
                        continue;

                if (udev_get_whole_disk(event->dev, NULL, &event_devname) <= 0)
                        continue;

                if (!streq(devname, event_devname))
                        continue;

                event->retry_again_next_usec = 0;
        }

        return 0;
}

static int event_queue_insert(Manager *manager, sd_device *dev) {
        const char *devpath, *devpath_old = NULL, *id = NULL, *devnode = NULL;
        sd_device_action_t action;
        uint64_t seqnum;
        Event *event;
        int r;

        assert(manager);
        assert(dev);

        /* We only accepts devices received by device monitor. */
        r = sd_device_get_seqnum(dev, &seqnum);
        if (r < 0)
                return r;

        r = sd_device_get_action(dev, &action);
        if (r < 0)
                return r;

        r = sd_device_get_devpath(dev, &devpath);
        if (r < 0)
                return r;

        r = sd_device_get_property_value(dev, "DEVPATH_OLD", &devpath_old);
        if (r < 0 && r != -ENOENT)
                return r;

        r = sd_device_get_device_id(dev, &id);
        if (r < 0 && r != -ENOENT)
                return r;

        r = sd_device_get_devname(dev, &devnode);
        if (r < 0 && r != -ENOENT)
                return r;

        event = new(Event, 1);
        if (!event)
                return -ENOMEM;

        *event = (Event) {
                .manager = manager,
                .dev = sd_device_ref(dev),
                .seqnum = seqnum,
                .action = action,
                .id = id,
                .devpath = devpath,
                .devpath_old = devpath_old,
                .devnode = devnode,
                .state = EVENT_QUEUED,
        };

        if (!manager->events) {
                r = touch("/run/udev/queue");
                if (r < 0)
                        log_warning_errno(r, "Failed to touch /run/udev/queue, ignoring: %m");
        }

        LIST_APPEND(event, manager->events, event);

        log_device_uevent(dev, "Device is queued");

        return 0;
}

static int on_uevent(sd_device_monitor *monitor, sd_device *dev, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        DEVICE_TRACE_POINT(kernel_uevent_received, dev);

        device_ensure_usec_initialized(dev, NULL);

        r = event_queue_insert(manager, dev);
        if (r < 0) {
                log_device_error_errno(dev, r, "Failed to insert device into event queue: %m");
                return 1;
        }

        (void) event_queue_assume_block_device_unlocked(manager, dev);

        return 1;
}

static int on_notify(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);
        int r;

        assert(fd >= 0);

        _cleanup_(pidref_done) PidRef sender = PIDREF_NULL;
        _cleanup_strv_free_ char **l = NULL;
        r = notify_recv_strv(fd, &l, /* ret_ucred= */ NULL, &sender);
        if (r == -EAGAIN)
                return 0;
        if (r < 0)
                return r;

        /* lookup worker who sent the signal */
        Worker *worker = hashmap_get(manager->workers, PID_TO_PTR(sender.pid));
        if (!worker) {
                log_warning("Received notify datagram of unknown process ["PID_FMT"], ignoring.", sender.pid);
                return 0;
        }

        const char *v = strv_env_get(l, "INOTIFY_WATCH_ADD");
        if (v) {
                (void) manager_save_watch(manager, worker->event->dev, v);
                return 0;
        }

        if (strv_contains(l, "INOTIFY_WATCH_REMOVE=1")) {
                (void) manager_remove_watch(manager, worker->event->dev);
                return 0;
        }

        if (strv_contains(l, "TRY_AGAIN=1"))
                /* Worker cannot lock the device. Requeue the event. */
                event_requeue(worker->event);
        else
                event_free(worker->event);

        /* Update the state of the worker. */
        if (worker->state == WORKER_KILLING) {
                worker->state = WORKER_KILLED;
                (void) kill(worker->pid, SIGTERM);
        } else if (worker->state != WORKER_KILLED)
                worker->state = WORKER_IDLE;

        return 0;
}

static int on_sigterm(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);

        manager_exit(manager);

        return 1;
}

static int on_sighup(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);

        manager_reload(manager, /* force = */ true);

        return 1;
}

static int on_sigchld(sd_event_source *s, const siginfo_t *si, void *userdata) {
        _cleanup_(worker_freep) Worker *worker = ASSERT_PTR(userdata);
        sd_device *dev = worker->event ? ASSERT_PTR(worker->event->dev) : NULL;
        int r;

        assert(si);

        switch (si->si_code) {
        case CLD_EXITED:
                if (si->si_status == 0) {
                        log_device_debug(dev, "Worker ["PID_FMT"] exited.", si->si_pid);
                        return 0;
                }

                log_device_warning(dev, "Worker ["PID_FMT"] exited with return code %i.",
                                   si->si_pid, si->si_status);
                if (!dev)
                        return 0;

                (void) device_add_exit_status(dev, si->si_status);
                break;

        case CLD_KILLED:
        case CLD_DUMPED:
                log_device_warning(dev, "Worker ["PID_FMT"] terminated by signal %i (%s).",
                                   si->si_pid, si->si_status, signal_to_string(si->si_status));
                if (!dev)
                        return 0;

                (void) device_add_signal(dev, si->si_status);
                break;

        default:
                assert_not_reached();
        }

        /* delete state from disk */
        device_delete_db(dev);
        device_tag_index(dev, NULL, false);

        r = device_monitor_send(worker->manager->monitor, NULL, dev);
        if (r < 0)
                log_device_warning_errno(dev, r, "Failed to broadcast event to libudev listeners, ignoring: %m");

        return 0;
}

static int on_post(sd_event_source *s, void *userdata) {
        Manager *manager = ASSERT_PTR(userdata);

        if (manager->events) {
                /* Try to process pending events if idle workers exist. Why is this necessary?
                 * When a worker finished an event and became idle, even if there was a pending event,
                 * the corresponding device might have been locked and the processing of the event
                 * delayed for a while, preventing the worker from processing the event immediately.
                 * Now, the device may be unlocked. Let's try again! */
                event_queue_start(manager);
                return 1;
        }

        /* There are no queued events. Let's remove /run/udev/queue and clean up the idle processes. */

        if (unlink("/run/udev/queue") < 0) {
                if (errno != ENOENT)
                        log_warning_errno(errno, "Failed to unlink /run/udev/queue, ignoring: %m");
        } else
                log_debug("No events are queued, removing /run/udev/queue.");

        if (!hashmap_isempty(manager->workers)) {
                /* There are idle workers */
                (void) event_reset_time_relative(manager->event, &manager->kill_workers_event,
                                                 CLOCK_MONOTONIC, 3 * USEC_PER_SEC, USEC_PER_SEC,
                                                 on_kill_workers_event, manager,
                                                 0, "kill-workers-event", false);
                return 1;
        }

        /* There are no idle workers. */

        if (manager->exit) {
                (void) manager_serialize(manager);
                return sd_event_exit(manager->event, 0);
        }

        if (manager->cgroup && set_isempty(manager->synthesize_change_child_event_sources))
                /* cleanup possible left-over processes in our cgroup */
                (void) cg_kill(manager->cgroup, SIGKILL, CGROUP_IGNORE_SELF, /* set=*/ NULL, /* kill_log= */ NULL, /* userdata= */ NULL);

        return 1;
}

Manager* manager_new(void) {
        Manager *manager;

        manager = new(Manager, 1);
        if (!manager)
                return NULL;

        *manager = (Manager) {
                .inotify_fd = -EBADF,
                .config_by_udev_conf = UDEV_CONFIG_INIT,
                .config_by_command = UDEV_CONFIG_INIT,
                .config_by_kernel = UDEV_CONFIG_INIT,
                .config_by_control = UDEV_CONFIG_INIT,
                .config = UDEV_CONFIG_INIT,
        };

        return manager;
}

static int manager_init_device_monitor(Manager *manager, int fd) {
        int r;

        assert(manager);

        /* This takes passed file descriptor on success. */

        if (fd >= 0) {
                if (manager->monitor)
                        return log_warning_errno(SYNTHETIC_ERRNO(EALREADY), "Received multiple netlink socket (%i), ignoring.", fd);

                r = sd_is_socket(fd, AF_NETLINK, SOCK_RAW, /* listening = */ -1);
                if (r < 0)
                        return log_warning_errno(r, "Failed to verify socket type of %i, ignoring: %m", fd);
                if (r == 0)
                        return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Received invalid netlink socket (%i), ignoring.", fd);
        } else {
                if (manager->monitor)
                        return 0;
        }

        r = device_monitor_new_full(&manager->monitor, MONITOR_GROUP_KERNEL, fd);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize device monitor: %m");

        return 0;
}

static int manager_listen_fds(Manager *manager) {
        int r;

        assert(manager);

        _cleanup_strv_free_ char **names = NULL;
        int n = sd_listen_fds_with_names(/* unset_environment = */ true, &names);
        if (n < 0)
                return n;

        for (int i = 0; i < n; i++) {
                int fd = SD_LISTEN_FDS_START + i;

                if (streq(names[i], "varlink"))
                        r = 0; /* The fd will be handled by sd_varlink_server_listen_auto(). */
                else if (streq(names[i], "systemd-udevd-control.socket"))
                        r = manager_init_ctrl(manager, fd);
                else if (streq(names[i], "systemd-udevd-kernel.socket"))
                        r = manager_init_device_monitor(manager, fd);
                else if (streq(names[i], "inotify"))
                        r = manager_init_inotify(manager, fd);
                else if (streq(names[i], "manager-serialization"))
                        r = manager_deserialize_fd(manager, &fd);
                else
                        r = log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                            "Received unexpected fd (%s), ignoring.", names[i]);
                if (r < 0)
                        close_and_notify_warn(fd, names[i]);
        }

        return 0;
}

int manager_init(Manager *manager) {
        int r;

        assert(manager);

        r = manager_listen_fds(manager);
        if (r < 0)
                return log_error_errno(r, "Failed to listen on fds: %m");

        _cleanup_free_ char *cgroup = NULL;
        r = cg_pid_get_path(SYSTEMD_CGROUP_CONTROLLER, 0, &cgroup);
        if (r < 0)
                log_debug_errno(r, "Failed to get cgroup, ignoring: %m");
        else if (endswith(cgroup, "/udev")) { /* If we are in a subcgroup /udev/ we assume it was delegated to us */
                log_debug("Running in delegated subcgroup '%s'.", cgroup);
                manager->cgroup = TAKE_PTR(cgroup);
        }

        return 0;
}

static int manager_start_device_monitor(Manager *manager) {
        int r;

        assert(manager);

        r = manager_init_device_monitor(manager, -EBADF);
        if (r < 0)
                return r;

        (void) sd_device_monitor_set_description(manager->monitor, "manager");

        r = sd_device_monitor_attach_event(manager->monitor, manager->event);
        if (r < 0)
                return log_error_errno(r, "Failed to attach event to device monitor: %m");

        r = sd_device_monitor_start(manager->monitor, on_uevent, manager);
        if (r < 0)
                return log_error_errno(r, "Failed to start device monitor: %m");

        return 0;
}

static int manager_start_notify_event(Manager *manager) {
        static const union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
                .un.sun_path = "/run/udev/notify",
        };

        int r;

        assert(manager);
        assert(manager->event);

        _cleanup_close_ int fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0)
                return log_error_errno(errno, "Failed to create notification socket: %m");

        (void) sockaddr_un_unlink(&sa.un);

        if (bind(fd, &sa.sa, SOCKADDR_UN_LEN(sa.un)) < 0)
                return log_error_errno(errno, "Failed to bind notification socket: %m");

        r = setsockopt_int(fd, SOL_SOCKET, SO_PASSCRED, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable SO_PASSCRED on notification socket: %m");

        r = setsockopt_int(fd, SOL_SOCKET, SO_PASSPIDFD, true);
        if (r < 0)
                log_debug_errno(r, "Failed to enable SO_PASSPIDFD on notification socket, ignoring. %m");

        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        r = sd_event_add_io(manager->event, &s, fd, EPOLLIN, on_notify, manager);
        if (r < 0)
                return log_error_errno(r, "Failed to create notification event source: %m");

        r = sd_event_source_set_io_fd_own(s, true);
        if (r < 0)
                return log_error_errno(r, "Failed to make notification event source own file descriptor: %m");

        TAKE_FD(fd);

        r = sd_event_source_set_floating(s, true);
        if (r < 0)
                return log_error_errno(r, "Failed to make notification event source floating: %m");

        return 0;
}

static int manager_setup_event(Manager *manager) {
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        int r;

        assert(manager);

        /* block SIGCHLD for listening child events. */
        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGCHLD) >= 0);

        r = sd_event_default(&e);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        r = sd_event_add_signal(e, /* ret_event_source = */ NULL, SIGINT | SD_EVENT_SIGNAL_PROCMASK, on_sigterm, manager);
        if (r < 0)
                return log_error_errno(r, "Failed to create SIGINT event source: %m");

        r = sd_event_add_signal(e, /* ret_event_source = */ NULL, SIGTERM | SD_EVENT_SIGNAL_PROCMASK, on_sigterm, manager);
        if (r < 0)
                return log_error_errno(r, "Failed to create SIGTERM event source: %m");

        r = sd_event_add_signal(e, /* ret_event_source = */ NULL, SIGHUP | SD_EVENT_SIGNAL_PROCMASK, on_sighup, manager);
        if (r < 0)
                return log_error_errno(r, "Failed to create SIGHUP event source: %m");

        r = sd_event_add_post(e, /* ret_event_source = */ NULL, on_post, manager);
        if (r < 0)
                return log_error_errno(r, "Failed to create post event source: %m");

        /* Eventually, we probably want to do more here on memory pressure, for example, kill idle workers immediately */
        r = sd_event_add_memory_pressure(e, /* ret_event_source= */ NULL, /* callback= */ NULL, /* userdata= */ NULL);
        if (r < 0)
                log_full_errno(ERRNO_IS_NOT_SUPPORTED(r) || ERRNO_IS_PRIVILEGE(r) || (r == -EHOSTDOWN) ? LOG_DEBUG : LOG_WARNING, r,
                               "Failed to allocate memory pressure watch, ignoring: %m");

        r = sd_event_add_signal(e, /* ret_event_source= */ NULL,
                                (SIGRTMIN+18) | SD_EVENT_SIGNAL_PROCMASK, sigrtmin18_handler, /* userdata= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate SIGRTMIN+18 event source, ignoring: %m");

        r = sd_event_set_watchdog(e, true);
        if (r < 0)
                return log_error_errno(r, "Failed to create watchdog event source: %m");

        manager->event = TAKE_PTR(e);
        return 0;
}

int manager_main(Manager *manager) {
        int r;

        assert(manager);

        r = manager_setup_event(manager);
        if (r < 0)
                return r;

        r = manager_start_ctrl(manager);
        if (r < 0)
                return r;

        r = manager_start_varlink_server(manager);
        if (r < 0)
                return r;

        r = manager_start_device_monitor(manager);
        if (r < 0)
                return r;

        r = manager_start_inotify(manager);
        if (r < 0)
                return r;

        r = manager_start_notify_event(manager);
        if (r < 0)
                return r;

        manager->last_usec = now(CLOCK_MONOTONIC);

        udev_builtin_init();

        r = udev_rules_load(&manager->rules, manager->config.resolve_name_timing, /* extra = */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to read udev rules: %m");

        r = udev_rules_apply_static_dev_perms(manager->rules);
        if (r < 0)
                log_warning_errno(r, "Failed to apply permissions on static device nodes, ignoring: %m");

        notify_ready(manager);

        r = sd_event_loop(manager->event);
        if (r < 0)
                log_error_errno(r, "Event loop failed: %m");

        (void) sd_notify(/* unset= */ false, NOTIFY_STOPPING);
        return r;
}
