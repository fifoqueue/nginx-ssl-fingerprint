/*
 * JA4L packet selection and rendering follow FoxIO's JA4+ reference.
 * Copyright (c) 2023-2026, FoxIO, LLC. All rights reserved. Patent pending.
 * See LICENSE-JA4PLUS and NOTICE.
 */

#include <nginx_ssl_fingerprint.h>
#include <ngx_event.h>
#if (NGX_QUIC)
#include <ngx_event_quic_connection.h>
#endif

#if (NGX_LINUX)
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <time.h>
#endif

typedef struct {
    ngx_str_t    interface;
    ngx_uint_t   max_flows;
    ngx_msec_t   timeout;
    ngx_uint_t   nsockets;
    ngx_socket_t *sockets;
    u_char      *ports;
    unsigned     loopback:1;
} ngx_ja4l_conf_t;

static void *ngx_ja4l_create_conf(ngx_cycle_t *cycle);
static char *ngx_ja4l_init_conf(ngx_cycle_t *cycle, void *conf);

static ngx_command_t ngx_ja4l_commands[] = {
    { ngx_string("ja4l_capture"), NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot, 0, offsetof(ngx_ja4l_conf_t, interface), NULL },
    { ngx_string("ja4l_max_flows"), NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot, 0, offsetof(ngx_ja4l_conf_t, max_flows), NULL },
    { ngx_string("ja4l_timeout"), NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot, 0, offsetof(ngx_ja4l_conf_t, timeout), NULL },
    ngx_null_command
};

static ngx_core_module_t ngx_ja4l_module_ctx = {
    ngx_string("ja4l"), ngx_ja4l_create_conf, ngx_ja4l_init_conf
};

ngx_module_t ngx_ja4l_module = {
    NGX_MODULE_V1,
    &ngx_ja4l_module_ctx,
    ngx_ja4l_commands,
    NGX_CORE_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

static void *
ngx_ja4l_create_conf(ngx_cycle_t *cycle)
{
    ngx_ja4l_conf_t *conf;

    conf = ngx_pcalloc(cycle->pool, sizeof(ngx_ja4l_conf_t));
    if (conf != NULL) {
        conf->max_flows = NGX_CONF_UNSET_UINT;
        conf->timeout = NGX_CONF_UNSET_MSEC;
    }
    return conf;
}

#if (NGX_LINUX)

typedef struct {
    u_char     client[16];
    u_char     server[16];
    uint16_t   client_port;
    uint16_t   server_port;
    u_char     family;
    u_char     protocol;
    u_char     cid_len;
    u_char     cid[20];
    u_char     reserved;
} ngx_ja4l_key_t;

typedef struct ngx_ja4l_flow_s ngx_ja4l_flow_t;

typedef struct {
    ngx_ja4l_flow_t *flow;
    uint64_t        time[6];
    u_char          ttl;      /* client's */
    ngx_str_t       value[2]; /* JA4L, delta */
    unsigned        failed:1;
    unsigned        quic:1;
} ngx_ja4l_ctx_t;

struct ngx_ja4l_flow_s {
    ngx_rbtree_node_t node;
    ngx_queue_t      queue;
    ngx_ja4l_key_t    key;
    ngx_ja4l_ctx_t   *ctx;
    ngx_msec_t       expires;
    uint64_t         time[6];
    uint32_t         isn[2];
    u_char           ttl;
    unsigned         ready:1;
};

typedef struct {
    ngx_ja4l_key_t key;
    const u_char *data;
    size_t        len;
    uint32_t      seq;
    uint32_t      ack;
    u_char        flags;
    u_char        ttl;
} ngx_ja4l_packet_t;

static ngx_ja4l_conf_t  *ngx_ja4l_conf;
static ngx_connection_t *ngx_ja4l_capture;
static ngx_rbtree_t     ngx_ja4l_tree;
static ngx_rbtree_node_t ngx_ja4l_sentinel;
static ngx_queue_t      ngx_ja4l_expiry;  /* unbound, oldest first */
static ngx_queue_t      ngx_ja4l_bound;   /* owned by a live connection */
static ngx_queue_t      ngx_ja4l_ready;
static ngx_uint_t       ngx_ja4l_nflows;
static ngx_flag_t       ngx_ja4l_discard;
static u_char          ngx_ja4l_buffer[65575];

static ngx_int_t ngx_ja4l_drain(void);
static void ngx_ja4l_read(ngx_event_t *ev);

static uint32_t
ngx_ja4l_u32(const u_char *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16)
           | ((uint32_t) p[2] << 8) | p[3];
}

static uint16_t
ngx_ja4l_u16(const u_char *p)
{
    return (uint16_t) (((uint16_t) p[0] << 8) | p[1]);
}

static void
ngx_ja4l_reverse(ngx_ja4l_key_t *key)
{
    u_char   addr[16];
    uint16_t port;

    ngx_memcpy(addr, key->client, 16);
    ngx_memcpy(key->client, key->server, 16);
    ngx_memcpy(key->server, addr, 16);
    port = key->client_port;
    key->client_port = key->server_port;
    key->server_port = port;
}

/*
 * SOCK_DGRAM packet sockets supply IP headers, without link-layer headers.
 * TCP may be truncated after its header by the filter; its payload length
 * comes from the IP header.  Malformed packets and fragments are ignored:
 * the kernel drops the former, and the latter carry no usable timing, so
 * neither may invalidate other flows (anyone can send them to the port).
 */
static ngx_int_t
ngx_ja4l_packet(const u_char *data, size_t len, ngx_ja4l_packet_t *pkt)
{
    size_t off, size, header;
    u_char next;

    ngx_memzero(pkt, sizeof(*pkt));
    if (len < 20) {
        return NGX_DECLINED;
    }
    if ((data[0] >> 4) == 4) {
        off = (data[0] & 15) * 4;
        size = ngx_ja4l_u16(data + 2);
        if (off < 20 || size < off || ngx_ja4l_u16(data + 6) & 0x3fff) {
            return NGX_DECLINED;
        }
        pkt->key.family = 4;
        ngx_memcpy(pkt->key.client, data + 12, 4);
        ngx_memcpy(pkt->key.server, data + 16, 4);
        pkt->ttl = data[8];
        next = data[9];

    } else if ((data[0] >> 4) == 6) {
        if (len < 40) {
            return NGX_DECLINED;
        }
        size = 40 + ngx_ja4l_u16(data + 4);
        if (size == 40) {
            return NGX_DECLINED;
        }
        pkt->key.family = 6;
        ngx_memcpy(pkt->key.client, data + 8, 16);
        ngx_memcpy(pkt->key.server, data + 24, 16);
        pkt->ttl = data[7];
        next = data[6];
        off = 40;
        while (next != IPPROTO_TCP && next != IPPROTO_UDP) {
            if (off + 8 > ngx_min(size, len)) {
                return NGX_DECLINED;
            }
            if (next == IPPROTO_HOPOPTS || next == IPPROTO_ROUTING
                || next == IPPROTO_DSTOPTS)
            {
                header = ((size_t) data[off + 1] + 1) * 8;
            } else if (next == IPPROTO_AH) {
                header = ((size_t) data[off + 1] + 2) * 4;
            } else {
                return NGX_DECLINED; /* including fragments */
            }
            if (header > size - off) {
                return NGX_DECLINED;
            }
            next = data[off];
            off += header;
        }
    } else {
        return NGX_DECLINED;
    }

    /* "len" bounds what may be read, "size" is what the sender transmitted */
    if (size - off < 8 || len < off + 8) {
        return NGX_DECLINED;
    }
    pkt->key.protocol = next;
    pkt->key.client_port = ngx_ja4l_u16(data + off);
    pkt->key.server_port = ngx_ja4l_u16(data + off + 2);
    if (next == IPPROTO_TCP) {
        if (size - off < 20 || len < off + 20) {
            return NGX_DECLINED;
        }
        header = (data[off + 12] >> 4) * 4;
        if (header < 20 || header > size - off) {
            return NGX_DECLINED;
        }
        pkt->seq = ngx_ja4l_u32(data + off + 4);
        pkt->ack = ngx_ja4l_u32(data + off + 8);
        pkt->flags = data[off + 13];
    } else if (next == IPPROTO_UDP) {
        header = 8;
        if (size > len || ngx_ja4l_u16(data + off + 4) != size - off) {
            return NGX_DECLINED;
        }
    } else {
        return NGX_DECLINED;
    }
    pkt->data = data + off + header; /* readable for UDP only */
    pkt->len = size - off - header;
    return NGX_OK;
}

static void
ngx_ja4l_insert(ngx_rbtree_node_t *root, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t **p;
    ngx_ja4l_flow_t    *one = (ngx_ja4l_flow_t *) node, *two;
    ngx_int_t          cmp;

    for ( ;; ) {
        two = (ngx_ja4l_flow_t *) root;
        cmp = node->key < root->key ? -1 : node->key > root->key ? 1
              : ngx_memcmp(&one->key, &two->key, sizeof(one->key));
        p = cmp < 0 ? &root->left : &root->right;
        if (*p == sentinel) {
            break;
        }
        root = *p;
    }
    *p = node;
    node->parent = root;
    node->left = node->right = sentinel;
    ngx_rbt_red(node);
}

static ngx_ja4l_flow_t *
ngx_ja4l_find(ngx_ja4l_key_t *key)
{
    ngx_rbtree_node_t *node;
    ngx_ja4l_flow_t   *flow;
    uint32_t          hash;
    ngx_int_t         cmp;

    hash = ngx_crc32_short((u_char *) key, sizeof(*key));
    node = ngx_ja4l_tree.root;
    while (node != ngx_ja4l_tree.sentinel) {
        flow = (ngx_ja4l_flow_t *) node;
        cmp = hash < node->key ? -1 : hash > node->key ? 1
              : ngx_memcmp(key, &flow->key, sizeof(*key));
        if (cmp == 0) {
            return flow;
        }
        node = cmp < 0 ? node->left : node->right;
    }
    return NULL;
}

static void
ngx_ja4l_remove(ngx_ja4l_flow_t *flow, ngx_flag_t failed)
{
    if (flow->ctx) {
        flow->ctx->flow = NULL;
        flow->ctx->failed = failed;
    }
    ngx_rbtree_delete(&ngx_ja4l_tree, &flow->node);
    ngx_queue_remove(&flow->queue);
    ngx_ja4l_nflows--;
    ngx_free(flow);
}

static void
ngx_ja4l_expire(ngx_flag_t all)
{
    ngx_ja4l_flow_t *flow;

    while (!ngx_queue_empty(&ngx_ja4l_expiry)) {
        flow = ngx_queue_data(ngx_queue_head(&ngx_ja4l_expiry),
                              ngx_ja4l_flow_t, queue);
        if (!all && (ngx_msec_int_t) (flow->expires - ngx_current_msec) > 0) {
            break;
        }
        ngx_ja4l_remove(flow, 1);
    }
    while (all && !ngx_queue_empty(&ngx_ja4l_bound)) {
        flow = ngx_queue_data(ngx_queue_head(&ngx_ja4l_bound),
                              ngx_ja4l_flow_t, queue);
        ngx_ja4l_remove(flow, 1);
    }
    while (all && !ngx_queue_empty(&ngx_ja4l_ready)) {
        flow = ngx_queue_data(ngx_queue_head(&ngx_ja4l_ready),
                              ngx_ja4l_flow_t, queue);
        ngx_ja4l_remove(flow, 1);
    }
}

static void
ngx_ja4l_finish(void)
{
    ngx_ja4l_flow_t *flow;

    while (!ngx_queue_empty(&ngx_ja4l_ready)) {
        flow = ngx_queue_data(ngx_queue_head(&ngx_ja4l_ready),
                              ngx_ja4l_flow_t, queue);
        ngx_ja4l_remove(flow, 0);
    }
}

static ngx_ja4l_flow_t *
ngx_ja4l_new(ngx_ja4l_key_t *key)
{
    ngx_ja4l_flow_t *flow;

    ngx_ja4l_expire(0);
    if (ngx_ja4l_nflows >= ngx_ja4l_conf->max_flows) {
        /*
         * Every worker sees every connection but binds only its own, so the
         * table is mostly other workers' flows; evict the oldest unbound one
         * rather than refuse, or load or a SYN flood would disable JA4L.
         */
        if (ngx_queue_empty(&ngx_ja4l_expiry)) {
            return NULL;
        }
        ngx_ja4l_remove(ngx_queue_data(ngx_queue_head(&ngx_ja4l_expiry),
                                       ngx_ja4l_flow_t, queue), 1);
    }
    flow = ngx_calloc(sizeof(*flow), ngx_ja4l_capture->log);
    if (flow == NULL) {
        return NULL;
    }
    flow->key = *key;
    flow->node.key = ngx_crc32_short((u_char *) key, sizeof(*key));
    flow->expires = ngx_current_msec + ngx_ja4l_conf->timeout;
    ngx_rbtree_insert(&ngx_ja4l_tree, &flow->node);
    ngx_queue_insert_tail(&ngx_ja4l_expiry, &flow->queue);
    ngx_ja4l_nflows++;
    return flow;
}

static void
ngx_ja4l_snapshot(ngx_ja4l_flow_t *flow)
{
    if (flow->ctx) {
        ngx_memcpy(flow->ctx->time, flow->time, sizeof(flow->time));
        flow->ctx->ttl = flow->ttl;
        if (!flow->ready
            && (flow->key.protocol == IPPROTO_UDP ? flow->time[3] : flow->time[5]))
        {
            ngx_queue_remove(&flow->queue);
            ngx_queue_insert_tail(&ngx_ja4l_ready, &flow->queue);
            flow->ready = 1;
        }
    }
}

static void
ngx_ja4l_tcp(ngx_ja4l_packet_t *pkt, uint64_t time, ngx_flag_t incoming)
{
    ngx_ja4l_flow_t *flow;
    ngx_flag_t      server;

    if ((pkt->flags & 0x12) == 0x02) {
        if (!incoming || !(ngx_ja4l_conf->ports[pkt->key.server_port] & 1)) {
            return;
        }
        flow = ngx_ja4l_find(&pkt->key);
        if (flow && flow->isn[0] != pkt->seq) {
            ngx_ja4l_remove(flow, 1);
            flow = NULL;
        }
        if (flow == NULL) {
            flow = ngx_ja4l_new(&pkt->key);
            if (flow == NULL) {
                return;
            }
            flow->isn[0] = pkt->seq;
            flow->time[0] = time;
            flow->ttl = pkt->ttl;
        }
        return;
    }

    server = 0;
    flow = ngx_ja4l_find(&pkt->key);
    if (flow == NULL) {
        ngx_ja4l_reverse(&pkt->key);
        flow = ngx_ja4l_find(&pkt->key);
        server = 1;
    }
    if (flow == NULL) {
        return;
    }
    if (time < flow->time[0] || (pkt->flags & 0x04)) {
        ngx_ja4l_remove(flow, 1);
        return;
    }
    if (server && (pkt->flags & 0x12) == 0x12 && !flow->time[1]
        && pkt->ack == flow->isn[0] + 1)
    {
        flow->isn[1] = pkt->seq;
        flow->time[1] = time;
    } else if (!server && (pkt->flags & 0x12) == 0x10 && !pkt->len
               && flow->time[1] && !flow->time[2]
               && pkt->seq == flow->isn[0] + 1 && pkt->ack == flow->isn[1] + 1)
    {
        if (time < flow->time[1]) {
            ngx_ja4l_remove(flow, 1);
            return;
        }
        flow->time[2] = time;
    } else if (pkt->len && flow->time[2] && !(pkt->flags & 0x02)) {
        if (time < flow->time[2]) {
            ngx_ja4l_remove(flow, 1);
            return;
        }
        if (!server && !flow->time[3]) {
            flow->time[3] = time;
        } else if (server && flow->time[3] && !flow->time[4]) {
            flow->time[4] = time;
        } else if (!server && flow->time[4] && !flow->time[5]) {
            flow->time[5] = time;
        }
    }
    ngx_ja4l_snapshot(flow);
}

static ngx_int_t
ngx_ja4l_varint(const u_char **p, const u_char *end, uint64_t *value)
{
    size_t n, i;

    if (*p == end) {
        return NGX_ERROR;
    }
    n = (size_t) 1 << (**p >> 6);
    if ((size_t) (end - *p) < n) {
        return NGX_ERROR;
    }
    *value = (*p)[0] & 63;
    for (i = 1; i < n; i++) {
        *value = (*value << 8) | (*p)[i];
    }
    *p += n;
    return NGX_OK;
}

static void
ngx_ja4l_quic(ngx_ja4l_packet_t *pkt, uint64_t time, ngx_flag_t incoming)
{
    const u_char   *p = pkt->data, *end = p + pkt->len, *dcid, *scid;
    ngx_ja4l_key_t  key;
    ngx_ja4l_flow_t *flow;
    ngx_flag_t      server;
    uint64_t        size;
    uint32_t        version;
    u_char          type, dlen, slen;

    while (p < end && (*p & 0xc0) == 0xc0) {
        if (end - p < 7) {
            return;
        }
        type = (*p >> 4) & 3;
        version = ngx_ja4l_u32(p + 1);
        if (version == 0x6b3343cf) {
            type = (type + 3) & 3;
        } else if (version != 1) {
            return;
        }
        dlen = p[5];
        p += 6;
        if (dlen > 20 || end - p < dlen + 1) {
            return;
        }
        dcid = p;
        p += dlen;
        slen = *p++;
        if (slen > 20 || end - p < slen) {
            return;
        }
        scid = p;
        p += slen;
        if (type == 3) {
            return; /* Retry is not a server Initial */
        }
        if (type == 0) {
            if (ngx_ja4l_varint(&p, end, &size) != NGX_OK
                || size > (uint64_t) (end - p))
            {
                return;
            }
            p += (size_t) size;
        }
        if (ngx_ja4l_varint(&p, end, &size) != NGX_OK
            || size == 0 || size > (uint64_t) (end - p))
        {
            return;
        }

        key = pkt->key;
        key.cid_len = slen;
        ngx_memcpy(key.cid, scid, slen);
        flow = ngx_ja4l_find(&key);
        server = 0;
        if (flow == NULL) {
            key = pkt->key;
            ngx_ja4l_reverse(&key);
            key.cid_len = dlen;
            ngx_memcpy(key.cid, dcid, dlen);
            flow = ngx_ja4l_find(&key);
            server = 1;
        }
        if (flow == NULL && incoming && type == 0
            && (ngx_ja4l_conf->ports[pkt->key.server_port] & 2))
        {
            key = pkt->key;
            key.cid_len = slen;
            ngx_memcpy(key.cid, scid, slen);
            flow = ngx_ja4l_new(&key);
            server = 0;
        }
        if (flow) {
            if (time < flow->time[0]) {
                ngx_ja4l_remove(flow, 1);
                return;
            }
            if (!server && type == 0 && !flow->time[0]) {
                flow->time[0] = time;
                flow->ttl = pkt->ttl;
            } else if (server && type == 0 && !flow->time[1]) {
                flow->time[1] = time;
            } else if (server && type == 2 && flow->time[1] && !flow->time[2]) {
                flow->time[2] = time;
            } else if (!server && type == 2 && flow->time[2] && !flow->time[3]) {
                flow->time[3] = time;
            }
            ngx_ja4l_snapshot(flow);
        }
        p += (size_t) size;
    }
}

static ngx_flag_t
ngx_ja4l_lost(void)
{
    struct tpacket_stats stats;
    socklen_t            len = sizeof(stats);

    ngx_memzero(&stats, sizeof(stats));
    return getsockopt(ngx_ja4l_capture->fd, SOL_PACKET, PACKET_STATISTICS,
                      &stats, &len) == -1 || stats.tp_drops != 0;
}

/* Drain before reading a variable, so nginx/request event ordering is irrelevant. */
static ngx_int_t
ngx_ja4l_drain(void)
{
    struct sockaddr_ll  addr;
    struct msghdr       msg;
    struct iovec        iov;
    struct cmsghdr     *cm;
    struct timespec     stamp;
    union {
        struct cmsghdr align;
        u_char data[CMSG_SPACE(sizeof(struct timespec))];
    } control;
    ngx_ja4l_packet_t pkt;
    ngx_uint_t       i;
    ssize_t          n;
    uint64_t         time;

    /* Drops are checked before trusting anything: at EAGAIN and at the cap. */
    for (i = 0; i < 2048; i++) {
        ngx_memzero(&msg, sizeof(msg));
        ngx_memzero(&stamp, sizeof(stamp));
        iov.iov_base = ngx_ja4l_buffer;
        iov.iov_len = sizeof(ngx_ja4l_buffer);
        msg.msg_name = &addr;
        msg.msg_namelen = sizeof(addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.data;
        msg.msg_controllen = sizeof(control.data);
        n = recvmsg(ngx_ja4l_capture->fd, &msg, MSG_DONTWAIT);
        if (n == -1) {
            if (ngx_socket_errno == NGX_EINTR) {
                continue;
            }
            if (ngx_socket_errno != NGX_EAGAIN) {
                ngx_ja4l_discard = 1;
                ngx_ja4l_expire(1);
                return NGX_ERROR;
            }
            if (ngx_ja4l_lost()) {
                ngx_ja4l_discard = 1;
                ngx_ja4l_expire(1);
                continue;
            }
            ngx_ja4l_discard = 0;
            ngx_ja4l_finish();
            return NGX_OK;
        }
        /* Loopback transmit taps share a timestamp before socket fanout;
         * receive copies may be restamped independently by the kernel. */
        if (ngx_ja4l_discard || addr.sll_pkttype == PACKET_OTHERHOST
            || (ngx_ja4l_conf->loopback && addr.sll_pkttype != PACKET_OUTGOING))
        {
            continue;
        }
        for (cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
            if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_TIMESTAMPNS
                && cm->cmsg_len >= CMSG_LEN(sizeof(stamp)))
            {
                ngx_memcpy(&stamp, CMSG_DATA(cm), sizeof(stamp));
            }
        }
        if ((msg.msg_flags & (MSG_TRUNC|MSG_CTRUNC)) || stamp.tv_sec <= 0
            || stamp.tv_nsec < 0 || stamp.tv_nsec >= 1000000000)
        {
            ngx_ja4l_discard = 1;
            ngx_ja4l_expire(1);
            continue;
        }
        time = (uint64_t) stamp.tv_sec * 1000000000 + stamp.tv_nsec;
        if (ngx_ja4l_packet(ngx_ja4l_buffer, (size_t) n, &pkt) != NGX_OK) {
            continue;
        }
        if (pkt.key.protocol == IPPROTO_TCP) {
            ngx_ja4l_tcp(&pkt, time, ngx_ja4l_conf->loopback
                         || addr.sll_pkttype != PACKET_OUTGOING);
        } else {
            ngx_ja4l_quic(&pkt, time, ngx_ja4l_conf->loopback
                          || addr.sll_pkttype != PACKET_OUTGOING);
        }
    }
    if (ngx_ja4l_lost()) {
        ngx_ja4l_discard = 1;
        ngx_ja4l_expire(1);
    }
    /* Bound work under floods; resume through nginx's next event iteration. */
    ngx_post_event(ngx_ja4l_capture->read, &ngx_posted_next_events);
    return NGX_AGAIN;
}

static void
ngx_ja4l_read(ngx_event_t *ev)
{
    if (ev->timedout) {
        ev->timedout = 0;
        ngx_ja4l_expire(0);
    }
    (void) ngx_ja4l_drain();
    if (!ev->timer_set) {
        ngx_add_timer(ev, 1000);
    }
}

static void
ngx_ja4l_connection_cleanup(void *data)
{
    ngx_ja4l_ctx_t *ctx = data;

    if (ctx->flow) {
        ngx_ja4l_remove(ctx->flow, 0);
    }
}

#if (NGX_QUIC)

static ngx_int_t
ngx_ja4l_address(struct sockaddr *sa, u_char *addr, uint16_t *port)
{
    struct sockaddr_in  *sin;
    struct sockaddr_in6 *sin6;

    if (sa->sa_family == AF_INET) {
        sin = (struct sockaddr_in *) sa;
        ngx_memcpy(addr, &sin->sin_addr, 4);
        *port = ntohs(sin->sin_port);
        return 4;
    }
    if (sa->sa_family == AF_INET6) {
        sin6 = (struct sockaddr_in6 *) sa;
        *port = ntohs(sin6->sin6_port);
        if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            ngx_memcpy(addr, sin6->sin6_addr.s6_addr + 12, 4);
            return 4;
        }
        ngx_memcpy(addr, &sin6->sin6_addr, 16);
        return 6;
    }
    return NGX_ERROR;
}

#endif

void
ngx_ja4l_bind(ngx_connection_t *c)
{
    ngx_ja4l_ctx_t   *ctx;
    ngx_ja4l_flow_t  *flow;
    ngx_ja4l_key_t    key;
    ngx_pool_cleanup_t *cleanup;
    ngx_ja4l_packet_t syn;
    ngx_int_t        rc;
#if (NGX_QUIC)
    ngx_int_t        family;
    ngx_quic_connection_t *qc;
#endif

    if (ngx_ja4l_capture == NULL || c->fp_ja4l != NULL) {
        return;
    }
    ngx_memzero(&key, sizeof(key));

    if (c->type == SOCK_STREAM) {
#if (NGX_HAVE_TCP_SAVE_SYN)
        /* The saved SYN carries the socket's own addresses, as captured. */
        if (c->saved_syn.data == NULL
            || ngx_ja4l_packet(c->saved_syn.data, c->saved_syn.len, &syn) != NGX_OK
            || syn.key.protocol != IPPROTO_TCP)
        {
            return;
        }
        key = syn.key;
#else
        return;
#endif
    } else {
#if (NGX_QUIC)
        qc = ngx_quic_get_connection(c);
        if (qc == NULL || qc->path == NULL || qc->path->cid == NULL
            || qc->path->cid->len > sizeof(key.cid)
            || c->sockaddr == NULL || c->local_sockaddr == NULL)
        {
            return;
        }
        family = ngx_ja4l_address(c->sockaddr, key.client, &key.client_port);
        if (family == NGX_ERROR
            || ngx_ja4l_address(c->local_sockaddr, key.server, &key.server_port) != family)
        {
            return;
        }
        key.family = (u_char) family;
        key.protocol = IPPROTO_UDP;
        /* ctp.initial_scid borrows the TLS parser buffer; path->cid owns the
         * same validated client CID for the lifetime of the handshake path. */
        key.cid_len = (u_char) qc->path->cid->len;
        ngx_memcpy(key.cid, qc->path->cid->id, key.cid_len);
#else
        return;
#endif
    }
    cleanup = ngx_pool_cleanup_add(c->pool, sizeof(ngx_ja4l_ctx_t));
    if (cleanup == NULL) {
        return;
    }
    ctx = cleanup->data;
    ngx_memzero(ctx, sizeof(*ctx));
    cleanup->handler = ngx_ja4l_connection_cleanup;
    c->fp_ja4l = ctx;
    ctx->failed = 1;
    ctx->quic = (key.protocol == IPPROTO_UDP);

    /* binding trusts no timestamps, so a drain stopped at its cap is fine */
    rc = ngx_ja4l_drain();
    if (rc == NGX_ERROR) {
        return;
    }
    flow = ngx_ja4l_find(&key);
    if (flow == NULL || flow->ctx != NULL
        || (!ctx->quic && flow->isn[0] != syn.seq))
    {
        return;
    }
    ctx->failed = 0;
    ctx->flow = flow;
    flow->ctx = ctx;
    ngx_queue_remove(&flow->queue);
    ngx_queue_insert_tail(&ngx_ja4l_bound, &flow->queue);
    ngx_ja4l_snapshot(flow);
    if (rc == NGX_OK) {
        ngx_ja4l_finish();
    }
}

ngx_int_t
ngx_ja4l(ngx_connection_t *c, ngx_str_t *out, ngx_uint_t which,
    ngx_flag_t plain_http)
{
    ngx_ja4l_ctx_t *ctx;
    ngx_str_t      values[2];
    uint64_t       transport, application, tenths;
    u_char        *p;

#if (NGX_QUIC)
    if (c->quic) {
        c = c->quic->parent;
    }
#endif
    if (ngx_ja4l_capture == NULL || which > 1 || c->fp_ja4l == NULL) {
        return NGX_DECLINED;
    }
    ctx = c->fp_ja4l;
    if (ctx->value[which].data != NULL) {
        *out = ctx->value[which];
        return NGX_OK;
    }
    if (ctx->value[0].data != NULL || ctx->failed
        || (ctx->flow && ngx_ja4l_drain() != NGX_OK) || ctx->failed)
    {
        return NGX_DECLINED;
    }
    if (!ctx->time[0] || !ctx->time[1] || !ctx->time[2] || !ctx->ttl
        || ctx->time[1] < ctx->time[0] || ctx->time[2] < ctx->time[1])
    {
        return NGX_DECLINED;
    }
    /* client one-way: SYN-ACK to ACK, or server to client Handshake */
    transport = ctx->time[2] - ctx->time[1];
    application = 0;
    if (ctx->quic) {
        if (!ctx->time[3] || ctx->time[3] < ctx->time[2]) {
            return NGX_DECLINED;
        }
        transport = ctx->time[3] - ctx->time[2];
    } else if (!plain_http) {
        if (!ctx->time[3] || !ctx->time[4] || !ctx->time[5]
            || ctx->time[4] < ctx->time[3] || ctx->time[5] < ctx->time[4])
        {
            return NGX_DECLINED;
        }
        application = ctx->time[5] - ctx->time[4];
    }
    ngx_memzero(values, sizeof(values));
    values[0].data = ngx_pnalloc(c->pool, NGX_INT64_LEN * 2 + 8);
    if (values[0].data == NULL) {
        return NGX_ERROR;
    }
    p = ngx_sprintf(values[0].data, "%uL_%ui_", transport / 2000,
                    (ngx_uint_t) ctx->ttl);
    if (ctx->quic) {
        p = ngx_cpymem(p, "quic", 4);
    } else if (plain_http) {
        p = ngx_cpymem(p, "tcp", 3);
    } else {
        p = ngx_sprintf(p, "%uL", application / 2000);
    }
    values[0].len = p - values[0].data;
    if (!ctx->quic && !plain_http && transport
        && application <= (UINT64_MAX - transport / 2) / 10)
    {
        tenths = (application * 10 + transport / 2) / transport;
        values[1].data = ngx_pnalloc(c->pool, NGX_INT64_LEN + 2);
        if (values[1].data == NULL) {
            return NGX_ERROR;
        }
        p = ngx_sprintf(values[1].data, "%uL.%uL", tenths / 10, tenths % 10);
        values[1].len = p - values[1].data;
    }
    ngx_memcpy(ctx->value, values, sizeof(values));
    if (ctx->flow) {
        ngx_ja4l_remove(ctx->flow, 0);
    }
    if (ctx->value[which].data == NULL) {
        return NGX_DECLINED;
    }
    *out = ctx->value[which];
    return NGX_OK;
}

/* Socket lifecycle and kernel filtering are kept in the core module so HTTP
 * and stream workers share one capture and the same measurement state. */

static void
ngx_ja4l_sockets_cleanup(void *data)
{
    ngx_ja4l_conf_t *conf = data;
    ngx_uint_t      i;

    for (i = 0; i < conf->nsockets; i++) {
        if (conf->sockets[i] != (ngx_socket_t) -1) {
            (void) ngx_close_socket(conf->sockets[i]);
            conf->sockets[i] = (ngx_socket_t) -1;
        }
    }
}

static char *
ngx_ja4l_init_conf(ngx_cycle_t *cycle, void *data)
{
    ngx_ja4l_conf_t  *conf = data;
    ngx_core_conf_t  *ccf;
    ngx_listening_t  *ls;
    ngx_pool_cleanup_t *cleanup;
    ngx_uint_t       i, port, count, n, match;
    int              value, index;
    ngx_socket_t     fd;
    struct sockaddr_ll address;
    struct ifreq     interface;
    struct sock_filter *code;
    struct sock_fprog filter;
    /*
     * Keep the kernel copy small: every worker receives every packet.  M[0]
     * holds the L4 protocol and X the L4 offset when the port list starts.
     */
    static const struct sock_filter prefix[] = {
        BPF_STMT(BPF_LD|BPF_B|BPF_ABS, 0),
        BPF_STMT(BPF_ALU|BPF_AND|BPF_K, 0xf0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0x40, 0, 6),
        BPF_STMT(BPF_LD|BPF_H|BPF_ABS, 6),
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, 0x3fff, 5, 0), /* fragments */
        BPF_STMT(BPF_LD|BPF_B|BPF_ABS, 9),
        BPF_STMT(BPF_LDX|BPF_B|BPF_MSH, 0),
        BPF_STMT(BPF_ST, 0),
        BPF_STMT(BPF_JMP|BPF_JA, 8),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0x60, 1, 0),
        BPF_STMT(BPF_RET|BPF_K, 0),
        BPF_STMT(BPF_LD|BPF_B|BPF_ABS, 6),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_TCP, 2, 0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_UDP, 1, 0),
        BPF_STMT(BPF_RET|BPF_K, 65575), /* IPv6 extension headers */
        BPF_STMT(BPF_ST, 0),
        BPF_STMT(BPF_LDX|BPF_IMM, 40)
    };
    static const struct sock_filter suffix[] = {
        BPF_STMT(BPF_RET|BPF_K, 0),
        BPF_STMT(BPF_LD|BPF_MEM, 0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_TCP, 0, 1),
        BPF_STMT(BPF_RET|BPF_K, 120), /* IPv4 + TCP headers at most */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_UDP, 0, 3),
        BPF_STMT(BPF_LD|BPF_B|BPF_IND, 8),
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, 0x80, 0, 1), /* QUIC long header */
        BPF_STMT(BPF_RET|BPF_K, 65575),
        BPF_STMT(BPF_RET|BPF_K, 0)
    };
#define NGX_JA4L_MAX_PORTS                                                    \
    ((BPF_MAXINSNS - sizeof(prefix) / sizeof(prefix[0]) - 2                   \
      - sizeof(suffix) / sizeof(suffix[0])) / 4)

    ngx_conf_init_uint_value(conf->max_flows, 16384);
    ngx_conf_init_msec_value(conf->timeout, 30000);
    if (conf->interface.len == 0) {
        return NGX_CONF_OK;
    }
    if (conf->interface.len >= IFNAMSIZ || !conf->max_flows || !conf->timeout) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "invalid JA4L capture settings");
        return NGX_CONF_ERROR;
    }
    if (ngx_process == NGX_PROCESS_SIGNALLER) {
        return NGX_CONF_OK;
    }
    index = if_nametoindex((char *) conf->interface.data);
    if (index == 0) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                      "JA4L interface %V not found", &conf->interface);
        return NGX_CONF_ERROR;
    }
    conf->ports = ngx_pcalloc(cycle->pool, 65536);
    if (conf->ports == NULL) {
        return NGX_CONF_ERROR;
    }
    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        if (ls[i].sockaddr->sa_family != AF_INET
            && ls[i].sockaddr->sa_family != AF_INET6)
        {
            continue;
        }
        port = ngx_inet_get_port(ls[i].sockaddr);
#if (NGX_HAVE_TCP_SAVE_SYN)
        if (ls[i].type == SOCK_STREAM && ls[i].save_syn) {
            conf->ports[port] |= 1;
        }
#endif
#if (NGX_QUIC)
        if (ls[i].quic) {
            conf->ports[port] |= 2;
        }
#endif
    }
    count = 0;
    for (port = 0; port < 65536; port++) {
        count += (conf->ports[port] != 0);
    }
    if (count == 0 || count > NGX_JA4L_MAX_PORTS) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "JA4L needs 1..%uz capture ports (TCP needs tcp_save_syn on)",
                      (size_t) NGX_JA4L_MAX_PORTS);
        return NGX_CONF_ERROR;
    }
    if (ngx_test_config) {
        return NGX_CONF_OK;
    }
    n = sizeof(prefix) / sizeof(prefix[0]) + 2 + 4 * count;
    code = ngx_pcalloc(cycle->pool, (n + sizeof(suffix) / sizeof(suffix[0]))
                                    * sizeof(*code));
    if (code == NULL) {
        return NGX_CONF_ERROR;
    }
    /* each matching port jumps to suffix[1], past the "no match" return */
    match = n + 1;
    ngx_memcpy(code, prefix, sizeof(prefix));
    n = sizeof(prefix) / sizeof(prefix[0]);
    for (i = 0; i < 2; i++) {
        code[n].code = BPF_LD|BPF_H|BPF_IND;
        code[n++].k = (uint32_t) (i * 2);
        for (port = 0; port < 65536; port++) {
            if (!conf->ports[port]) {
                continue;
            }
            code[n].code = BPF_JMP|BPF_JEQ|BPF_K;
            code[n].jf = 1;
            code[n++].k = (uint32_t) port;
            code[n].code = BPF_JMP|BPF_JA;
            code[n].k = (uint32_t) (match - n - 1);
            n++;
        }
    }
    ngx_memcpy(code + n, suffix, sizeof(suffix));
    n += sizeof(suffix) / sizeof(suffix[0]);
    filter.len = (unsigned short) n;
    filter.filter = code;

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
    conf->nsockets = ccf->master ? ccf->worker_processes : 1;
    conf->sockets = ngx_palloc(cycle->pool, conf->nsockets * sizeof(ngx_socket_t));
    if (conf->sockets == NULL) {
        return NGX_CONF_ERROR;
    }
    for (i = 0; i < conf->nsockets; i++) {
        conf->sockets[i] = (ngx_socket_t) -1;
    }
    cleanup = ngx_pool_cleanup_add(cycle->pool, 0);
    if (cleanup == NULL) {
        return NGX_CONF_ERROR;
    }
    cleanup->data = conf;
    cleanup->handler = ngx_ja4l_sockets_cleanup;

    /* ponytail: each worker observes the selected ports independently; use a
     * dedicated capture service if duplication at large worker counts matters. */
    for (i = 0; i < conf->nsockets; i++) {
        fd = socket(AF_PACKET, SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
        if (fd == (ngx_socket_t) -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                          "JA4L packet socket failed (master needs CAP_NET_RAW)");
            return NGX_CONF_ERROR;
        }
        conf->sockets[i] = fd;
        value = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPNS, &value, sizeof(value)) == -1
            || setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) == -1
            || setsockopt(fd, SOL_SOCKET, SO_LOCK_FILTER, &value, sizeof(value)) == -1)
        {
            goto failed;
        }
        value = 2 * 1024 * 1024;
        /* SO_RCVBUF is silently capped by net.core.rmem_max (208K default);
         * any queue drop discards every flow, so use the root master's
         * CAP_NET_ADMIN to bypass it where available. */
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &value, sizeof(value)) == -1
            && setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &value, sizeof(value)) == -1)
        {
            goto failed;
        }
        ngx_memzero(&interface, sizeof(interface));
        ngx_cpystrn((u_char *) interface.ifr_name, conf->interface.data, IFNAMSIZ);
        if (ioctl(fd, SIOCGIFFLAGS, &interface) == -1) {
            goto failed;
        }
        conf->loopback = (interface.ifr_flags & IFF_LOOPBACK) != 0;
        ngx_memzero(&address, sizeof(address));
        address.sll_family = AF_PACKET;
        address.sll_protocol = htons(ETH_P_ALL);
        address.sll_ifindex = index;
        if (bind(fd, (struct sockaddr *) &address, sizeof(address)) == -1) {
            goto failed;
        }
    }
    return NGX_CONF_OK;

failed:

    ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                  "JA4L capture socket setup failed");
    return NGX_CONF_ERROR;
}

/* Called by the HTTP module after nginx has initialized its event backend. */
ngx_int_t
ngx_ja4l_init_process(ngx_cycle_t *cycle)
{
    ngx_ja4l_conf_t  *conf;
    ngx_uint_t       i, worker;
    ngx_connection_t *c;

    conf = (ngx_ja4l_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_ja4l_module);
    if (conf->nsockets == 0) {
        return NGX_OK;
    }
    if (ngx_process != NGX_PROCESS_WORKER && ngx_process != NGX_PROCESS_SINGLE) {
        ngx_ja4l_sockets_cleanup(conf);
        return NGX_OK;
    }
    worker = ngx_process == NGX_PROCESS_SINGLE ? 0 : ngx_worker;
    if (worker >= conf->nsockets) {
        return NGX_ERROR;
    }
    for (i = 0; i < conf->nsockets; i++) {
        if (i != worker) {
            (void) ngx_close_socket(conf->sockets[i]);
            conf->sockets[i] = (ngx_socket_t) -1;
        }
    }
    c = ngx_get_connection(conf->sockets[worker], cycle->log);
    if (c == NULL) {
        return NGX_ERROR;
    }
    ngx_ja4l_conf = conf;
    ngx_ja4l_capture = c;
    ngx_ja4l_nflows = 0;
    ngx_ja4l_discard = 0;
    ngx_rbtree_init(&ngx_ja4l_tree, &ngx_ja4l_sentinel, ngx_ja4l_insert);
    ngx_queue_init(&ngx_ja4l_expiry);
    ngx_queue_init(&ngx_ja4l_bound);
    ngx_queue_init(&ngx_ja4l_ready);
    c->log = cycle->log;
    c->read->log = cycle->log;
    c->read->handler = ngx_ja4l_read;
    c->read->cancelable = 1;
    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        return NGX_ERROR;
    }
    ngx_add_timer(c->read, 1000);
    return NGX_OK;
}

void
ngx_ja4l_exit_process(ngx_cycle_t *cycle)
{
    if (ngx_ja4l_capture == NULL) {
        return;
    }
    ngx_ja4l_expire(1);
    ngx_ja4l_conf->sockets[ngx_process == NGX_PROCESS_SINGLE ? 0 : ngx_worker] = -1;
    ngx_close_connection(ngx_ja4l_capture);
    ngx_ja4l_capture = NULL;
    ngx_ja4l_conf = NULL;
}

#else

static char *
ngx_ja4l_init_conf(ngx_cycle_t *cycle, void *data)
{
    ngx_ja4l_conf_t *conf = data;

    if (conf->interface.len) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "ja4l_capture requires Linux");
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

ngx_int_t
ngx_ja4l_init_process(ngx_cycle_t *cycle)
{
    return NGX_OK;
}

void
ngx_ja4l_exit_process(ngx_cycle_t *cycle)
{
}

void
ngx_ja4l_bind(ngx_connection_t *c)
{
}

ngx_int_t
ngx_ja4l(ngx_connection_t *c, ngx_str_t *out, ngx_uint_t which,
    ngx_flag_t plain_http)
{
    return NGX_DECLINED;
}

#endif
