/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/ioctl.h>
#include <linux/sockios.h>

#include "sd-varlink.h"

#include "journald-server.h"
#include "journald-stream.h"
#include "journald-sync.h"
#include "journald-varlink.h"
#include "time-util.h"

StreamSyncReq *stream_sync_req_free(StreamSyncReq *ssr) {
        if (!ssr)
                return NULL;

        if (ssr->req)
                LIST_REMOVE(by_sync_req, ssr->req->stream_sync_reqs, ssr);
        if (ssr->stream)
                LIST_REMOVE(by_stdout_stream, ssr->stream->stream_sync_reqs, ssr);

        return mfree(ssr);
}

void stream_sync_req_advance(StreamSyncReq *ssr, size_t p) {
        assert(ssr);

        /* Subtract the specified number of bytes from the byte counter. And when we hit zero we consider
         * this stream processed for the synchronization request */

        /* NB: This might invalidate the 'ssr' object! */

        if (p < ssr->pending_siocinq) {
                ssr->pending_siocinq -= p;
                return;
        }

        SyncReq *req = ASSERT_PTR(ssr->req);
        stream_sync_req_free(TAKE_PTR(ssr));

        /* Maybe we are done now? */
        sync_req_revalidate(TAKE_PTR(req));
}

static bool sync_req_is_complete(SyncReq *req) {
        int r;

        assert(req);
        assert(req->server);

        if (req->prioq_idx) {
                /* If this sync request is still in the priority queue it means we still need to check if
                 * incoming message timestamps are now newer than then sync request timestamp. */

                if (req->server->native_event_source) {
                        uint32_t revents = 0;

                        r = sd_event_source_get_io_revents(req->server->native_event_source, &revents);
                        if (r < 0 && r != -ENODATA)
                                log_debug_errno(r, "Failed to determine pending IO events of native socket, ignoring: %m");

                        if (FLAGS_SET(revents, EPOLLIN) &&
                            req->server->native_timestamp < req->timestamp)
                                return false;
                }

                if (req->server->syslog_event_source) {
                        uint32_t revents = 0;

                        r = sd_event_source_get_io_revents(req->server->syslog_event_source, &revents);
                        if (r < 0 && r != -ENODATA)
                                log_debug_errno(r, "Failed to determine pending IO events of syslog socket, ignoring: %m");

                        if (FLAGS_SET(revents, EPOLLIN) &&
                            req->server->syslog_timestamp < req->timestamp)
                                return false;
                }

                /* This sync request is fulfilled for the native + syslog datagram streams? Then, let's
                 * remove this sync request from the priority queue, so that we dont need to consider it
                 * anymore. */
                assert(prioq_remove(req->server->sync_req_prioq, req, &req->prioq_idx) > 0);
        }

        /* If there are still streams with pending counters, we still need to look into things */
        if (req->stream_sync_reqs)
                return false;

        return true;
}

static int on_idle(sd_event_source *s, void *userdata) {
        SyncReq *req = ASSERT_PTR(userdata);

        req->idle_event_source = sd_event_source_disable_unref(req->idle_event_source);

        /* When this idle event triggers, then we definitely are done with the synchronization request. This
         * is a safety net of a kind, to ensure we'll definitely put an end to any synchronization request,
         * even if we are confused by CLOCK_REALTIME jumps or similar. */
        sync_req_varlink_reply(TAKE_PTR(req));
        return 0;
}

SyncReq* sync_req_free(SyncReq *req) {
        if (!req)
                return NULL;

        if (req->server)
                assert_se(prioq_remove(req->server->sync_req_prioq, req, &req->prioq_idx) > 0);

        req->idle_event_source = sd_event_source_disable_unref(req->idle_event_source);

        sd_varlink_unref(req->link);

        while (req->stream_sync_reqs)
                stream_sync_req_free(req->stream_sync_reqs);

        return mfree(req);
}

static int sync_req_compare(const void *a, const void *b) {
        const SyncReq *x = a, *y = b;

        return CMP(x->timestamp, y->timestamp);
}

int sync_req_new(Server *s, sd_varlink *link, SyncReq **ret) {
        int r;

        assert(s);
        assert(link);
        assert(ret);

        _cleanup_(sync_req_freep) SyncReq *req = new(SyncReq, 1);
        if (!req)
                return -ENOMEM;

        *req = (SyncReq) {
                .server = s,
                .link = sd_varlink_ref(link),
                .prioq_idx = PRIOQ_IDX_NULL,
        };

        /* We use three distinct mechanism to determine when the synchronization request is complete:
         *
         * 1. For the syslog/native AF_UNIX/SOCK_DGRAM sockets we look at the datagram timestamps: once the
         *    most recently seen datagram on the socket is newer than the timestamp when we initiated the
         *    requested we know that all previously enqueued messages have been processed by us.
         *
         * 2. For the stream AF_UNIX/SOCK_STREAM sockets we have no timestamps. For them we take the SIOCINQ
         *    counter at the moment the synchronization request was enqueued. And once we processed the
         *    indicated number of input bytes we know that anything further was enqueued later than the
         *    original synchronization request timestamp we started from.
         *
         * 3. Finally, as safety net we install an idle handler with a very low priority (lower than the
         *    syslog/native/stream IO handlers). If this handler is called we know that there's no pending
         *    IO, hence everything so far queued is definitely processed.
         *
         * Note the asymmetry: for AF_UNIX/SOCK_DGRAM we go by timestamp, for AF_UNIX/SOCK_STREAM we count
         * bytes. That's because for SOCK_STREAM we have no timestamps, and for SOCK_DGRAM we have no API to
         * query all pending bytes (as SIOCINQ on SOCK_DGRAM reports size of next datagram, not size of all
         * pending datagrams). Ideally, we'd actually use neither of this, and the kernel would provide us
         * CLOCK_MONOTONIC timestamps... */

        req->timestamp = now(CLOCK_REALTIME);

        r = prioq_ensure_put(&s->sync_req_prioq, sync_req_compare, req, &req->prioq_idx);
        if (r < 0)
                return r;

        r = sd_event_add_defer(s->event, &req->idle_event_source, on_idle, req);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(req->idle_event_source, SD_EVENT_PRIORITY_NORMAL+15);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(req->idle_event_source, "deferred-sync");

        /* Now determine the pending byte counter for each stdout stream. If non-zero allocate a
         * StreamSyncReq for the stream to keep track of it */
        LIST_FOREACH(stdout_stream, ss, s->stdout_streams) {
                int v = 0;

                if (ioctl(ss->fd, SIOCINQ, &v) < 0)
                        log_debug_errno(errno, "Failed to issue SIOCINQ on stream socket, ignoring: %m");

                if (v <= 0)
                        continue;

                _cleanup_(stream_sync_req_freep) StreamSyncReq *ssr = new(StreamSyncReq, 1);
                if (!ssr)
                        return -ENOMEM;

                *ssr = (StreamSyncReq) {
                        .stream = ss,
                        .pending_siocinq = v,
                        .req = req,
                };

                LIST_PREPEND(by_sync_req, req->stream_sync_reqs, ssr);
                LIST_PREPEND(by_stdout_stream, ss->stream_sync_reqs, ssr);
        }

        *ret = TAKE_PTR(req);
        return 0;
}

bool sync_req_revalidate(SyncReq *req) {
        assert(req);

        /* Check if the synchronization request is complete now. If so, answer the Varlink client */

        if (!sync_req_is_complete(req))
                return false;

        sync_req_varlink_reply(TAKE_PTR(req));
        return true;
}

void sync_req_revalidate_by_timestamp(Server *s) {
        assert(s);

        /* Go through the pending sync requests by timestamp, and complete those for which a sync is now
         * complete. */

        SyncReq *req;
        while ((req = prioq_peek(s->sync_req_prioq)))
                if (!sync_req_revalidate(req))
                        break;
}
