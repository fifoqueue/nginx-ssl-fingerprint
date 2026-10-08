/*
 * JA4+ algorithms and adapted method/cookie/SYN handling:
 * Copyright (c) 2023-2026, FoxIO, LLC. All rights reserved. Patent pending.
 * Licensed under FoxIO License 1.1; see LICENSE-JA4PLUS and NOTICE.
 */

#include <nginx_ssl_fingerprint.h>
#include <openssl/sha.h>

extern ngx_module_t ngx_http_ssl_fingerprint_module;

static ngx_int_t
ngx_ja4_hash(const ngx_str_t *in, u_char *out)
{
    u_char  digest[SHA256_DIGEST_LENGTH];

    if (in->len == 0) {
        ngx_memset(out, '0', 12);
        return NGX_OK;
    }
    if (SHA256(in->data, in->len, digest) == NULL) {
        return NGX_ERROR;
    }
    ngx_hex_dump(out, digest, 6);
    return NGX_OK;
}

static ngx_ssl_fingerprint_extra_t *
ngx_ja4_extra(ngx_connection_t *c)
{
    if (c->ssl->fp_extra == NULL) {
        c->ssl->fp_extra = ngx_pcalloc(NGX_SSL_FP_POOL(c),
                                      sizeof(ngx_ssl_fingerprint_extra_t));
    }
    return c->ssl->fp_extra;
}

/* OID value octets, not text names, values, or the DER tag/length. */
static ngx_int_t
ngx_ja4x_oids(ngx_pool_t *pool, X509 *cert, ngx_uint_t part, ngx_str_t *out)
{
    const X509_NAME    *name;
    const ASN1_OBJECT  *oid;
    int           i, count;
    size_t        size, n;
    u_char       *p;

    name = part == 0 ? X509_get_issuer_name(cert) : X509_get_subject_name(cert);
    count = part == 2 ? X509_get_ext_count(cert) : X509_NAME_entry_count(name);
    size = 0;
    for (i = 0; i < count; i++) {
        oid = part == 2 ? X509_EXTENSION_get_object(X509_get_ext(cert, i))
                       : X509_NAME_ENTRY_get_object(X509_NAME_get_entry(name, i));
        n = OBJ_length(oid);
        if (n == 0 || n > (NGX_MAX_SIZE_T_VALUE - size - 1) / 2) {
            return NGX_ERROR;
        }
        size += 2 * n + 1;
    }
    out->data = ngx_pnalloc(pool, size ? size : 1);
    if (out->data == NULL) {
        return NGX_ERROR;
    }
    p = out->data;
    for (i = 0; i < count; i++) {
        if (i) {
            *p++ = ',';
        }
        oid = part == 2 ? X509_EXTENSION_get_object(X509_get_ext(cert, i))
                       : X509_NAME_ENTRY_get_object(X509_NAME_get_entry(name, i));
        p = ngx_hex_dump(p, (u_char *) OBJ_get0_data(oid), OBJ_length(oid));
    }
    out->len = p - out->data;
    return NGX_OK;
}

ngx_int_t
ngx_ssl_client_ja4x(ngx_connection_t *c, ngx_str_t *out, ngx_flag_t raw)
{
    X509                        *cert;
    ngx_uint_t                   i;
    ngx_str_t                    parts[3], hash, text;
    ngx_pool_t                  *pool;
    u_char                      *p;
    ngx_ssl_fingerprint_extra_t *fp;

    if (c->ssl == NULL || !c->ssl->handshaked) {
        return NGX_DECLINED;
    }
    fp = ngx_ja4_extra(c);
    if (fp == NULL) {
        return NGX_ERROR;
    }
    if (fp->client_ja4x.data == NULL) {
        cert = SSL_get0_peer_certificate(c->ssl->connection);
        if (cert == NULL) {
            return NGX_DECLINED;
        }
        pool = NGX_SSL_FP_POOL(c);
        for (i = 0; i < 3; i++) {
            if (ngx_ja4x_oids(pool, cert, i, &parts[i]) != NGX_OK) {
                return NGX_ERROR;
            }
        }
        hash.data = ngx_pnalloc(pool, 38);
        text.data = ngx_pnalloc(pool, parts[0].len + parts[1].len + parts[2].len + 2);
        if (hash.data == NULL || text.data == NULL) {
            return NGX_ERROR;
        }
        p = text.data;
        for (i = 0; i < 3; i++) {
            if (i) {
                *p++ = '_';
                hash.data[i * 13 - 1] = '_';
            }
            p = ngx_cpymem(p, parts[i].data, parts[i].len);
            if (ngx_ja4_hash(&parts[i], hash.data + i * 13) != NGX_OK) {
                return NGX_ERROR;
            }
        }
        hash.len = 38;
        text.len = p - text.data;
        fp->client_ja4x = hash;
        fp->client_ja4x_raw = text;
    }
    *out = raw ? fp->client_ja4x_raw : fp->client_ja4x;
    return NGX_OK;
}

typedef struct {
    ngx_str_t  pair;
    size_t     name_len;
    ngx_uint_t order;
} ngx_ja4h_cookie_t;

typedef struct {
    ngx_str_t  hash;
    ngx_str_t  raw;
} ngx_ja4h_ctx_t;

static int
ngx_ja4h_cookie_compare(const void *a, const void *b)
{
    const ngx_ja4h_cookie_t *one = a, *two = b;
    int                     rc;

    rc = ngx_memn2cmp(one->pair.data, two->pair.data, one->name_len, two->name_len);
    if (rc) {
        return rc;
    }
    /* Preserve wire order for duplicate names (qsort itself is not stable). */
    return (one->order > two->order) - (one->order < two->order);
}

static ngx_flag_t
ngx_ja4h_header(ngx_table_elt_t *h, const char *name, size_t len)
{
    return h->key.len == len && ngx_strncasecmp(h->key.data, (u_char *) name, len) == 0;
}

static void
ngx_ja4h_language(ngx_str_t *value, u_char *out)
{
    size_t              i, n;
    u_char              ch;
    static const u_char hex[] = "0123456789abcdef";

    for (i = 0, n = 0; i < value->len && n < 4; i++) {
        ch = value->data[i];
        if (ch == ',' || ch == ';') {
            break;
        }
        if (ch == '-' || ch == ' ' || (ch >= '\t' && ch <= '\r')) {
            continue;
        }
        ch = ngx_tolower(ch);
        if (ch >= 'a' && ch <= 'z') {
            out[n++] = ch;
        } else {
            out[n++] = hex[ch >> 4];
            if (n < 4) {
                out[n++] = hex[ch & 15];
            }
        }
    }
}

/* JA4H method codes from FoxIO's Wireshark implementation. */
static const struct {
    ngx_str_t method;
    u_char    code[3];
} ngx_ja4h_methods[] = {
    { ngx_string("ACL"), "ac" },
    { ngx_string("BASELINE-CONTROL"), "ba" },
    { ngx_string("BIND"), "bi" },
    { ngx_string("CHECKIN"), "cn" },
    { ngx_string("CHECKOUT"), "ct" },
    { ngx_string("CONNECT"), "co" },
    { ngx_string("COPY"), "cy" },
    { ngx_string("DELETE"), "de" },
    { ngx_string("GET"), "ge" },
    { ngx_string("HEAD"), "he" },
    { ngx_string("LABEL"), "la" },
    { ngx_string("LINK"), "li" },
    { ngx_string("LOCK"), "lo" },
    { ngx_string("MERGE"), "me" },
    { ngx_string("MKACTIVITY"), "ma" },
    { ngx_string("MKCALENDAR"), "mc" },
    { ngx_string("MKCOL"), "ml" },
    { ngx_string("MKREDIRECTREF"), "mr" },
    { ngx_string("MKWORKSPACE"), "mw" },
    { ngx_string("MOVE"), "mo" },
    { ngx_string("M-SEARCH"), "ms" },
    { ngx_string("NOTIFY"), "no" },
    { ngx_string("OPTIONS"), "op" },
    { ngx_string("PATCH"), "pa" },
    { ngx_string("POST"), "po" },
    { ngx_string("PRI"), "pr" },
    { ngx_string("PROPFIND"), "pf" },
    { ngx_string("PROPPATCH"), "pp" },
    { ngx_string("PURGE"), "pr" },
    { ngx_string("PUT"), "pu" },
    { ngx_string("REBIND"), "rb" },
    { ngx_string("REPORT"), "rp" },
    { ngx_string("SEARCH"), "se" },
    { ngx_string("SUBSCRIBE"), "su" },
    { ngx_string("TRACE"), "tr" },
    { ngx_string("UNBIND"), "ub" },
    { ngx_string("UNCHECKOUT"), "uc" },
    { ngx_string("UNLINK"), "ui" },
    { ngx_string("UNLOCK"), "uo" },
    { ngx_string("UNSUBSCRIBE"), "un" },
    { ngx_string("UPDATE"), "up" },
    { ngx_string("UPDATEREDIRECTREF"), "ur" },
    { ngx_string("VERSION-CONTROL"), "ve" }
};

ngx_int_t
ngx_http_ja4h(ngx_http_request_t *r, ngx_str_t *out, ngx_flag_t raw)
{
    ngx_ja4h_ctx_t    *ctx;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;
    ngx_array_t       cookies;
    ngx_ja4h_cookie_t *cookie;
    ngx_str_t         components[3];
    ngx_uint_t        i, j, count;
    size_t            size, names_size, pairs_size;
    u_char           *p, *start, *end, *next, *eq, prefix[] = "0000nn000000";
    ngx_flag_t        lang;

    r = r->main;
    ctx = ngx_http_get_module_ctx(r, ngx_http_ssl_fingerprint_module);
    if (ctx != NULL) {
        *out = raw ? ctx->raw : ctx->hash;
        return NGX_OK;
    }
    if (r->http_version < NGX_HTTP_VERSION_10) {
        return NGX_DECLINED;
    }
    for (i = 0; i < sizeof(ngx_ja4h_methods) / sizeof(ngx_ja4h_methods[0]); i++) {
        if (r->method_name.len == ngx_ja4h_methods[i].method.len
            && ngx_strncasecmp(r->method_name.data, ngx_ja4h_methods[i].method.data,
                               r->method_name.len) == 0)
        {
            ngx_memcpy(prefix, ngx_ja4h_methods[i].code, 2);
            break;
        }
    }
    prefix[2] = '0' + r->http_version / 1000;
    prefix[3] = '0' + r->http_version % 1000;
    size = names_size = pairs_size = count = lang = 0;
    if (ngx_array_init(&cookies, r->pool, 4, sizeof(ngx_ja4h_cookie_t)) != NGX_OK) {
        return NGX_ERROR;
    }

    for (part = &r->headers_in.headers.part; part; part = part->next) {
        h = part->elts;
        for (i = 0; i < part->nelts; i++) {
            if (&h[i] == r->fp_synthetic_host) {
                continue;
            }
            if (ngx_ja4h_header(&h[i], "cookie", 6)) {
                prefix[4] = 'c';
                start = h[i].value.data;
                end = start + h[i].value.len;
                while (start < end) {
                    next = ngx_strlchr(start, end, ';');
                    if (next == NULL) {
                        next = end;
                    }
                    p = next;
                    while (start < p && (*start == ' ' || *start == '\t')) {
                        start++;
                    }
                    while (p > start && (p[-1] == ' ' || p[-1] == '\t')) {
                        p--;
                    }
                    if (p > start) {
                        cookie = ngx_array_push(&cookies);
                        if (cookie == NULL) {
                            return NGX_ERROR;
                        }
                        cookie->pair.data = start;
                        cookie->pair.len = p - start;
                        eq = ngx_strlchr(start, p, '=');
                        cookie->name_len = (eq ? eq : p) - start;
                        cookie->order = cookies.nelts;
                        names_size += cookie->name_len + 1;
                        pairs_size += cookie->pair.len + 1;
                    }
                    start = next == end ? end : next + 1;
                }
                continue;
            }
            if (ngx_ja4h_header(&h[i], "referer", 7)) {
                prefix[5] = 'r';
                continue;
            }
            if (!lang && ngx_ja4h_header(&h[i], "accept-language", 15)) {
                ngx_ja4h_language(&h[i].value, prefix + 8);
                lang = 1;
            }
            size += h[i].key.len + 1;
            count++;
        }
    }
    count = ngx_min(count, 99);
    prefix[6] = '0' + count / 10;
    prefix[7] = '0' + count % 10;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_ja4h_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    ctx->raw.data = ngx_pnalloc(r->pool, 15 + size + names_size + pairs_size);
    ctx->hash.data = ngx_pnalloc(r->pool, 51);
    if (ctx->raw.data == NULL || ctx->hash.data == NULL) {
        return NGX_ERROR;
    }
    p = ngx_cpymem(ctx->raw.data, prefix, 12);
    *p++ = '_';
    components[0].data = p;
    for (part = &r->headers_in.headers.part; part; part = part->next) {
        h = part->elts;
        for (i = 0; i < part->nelts; i++) {
            if (&h[i] == r->fp_synthetic_host
                || ngx_ja4h_header(&h[i], "cookie", 6)
                || ngx_ja4h_header(&h[i], "referer", 7))
            {
                continue;
            }
            if (p != components[0].data) {
                *p++ = ',';
            }
            p = ngx_cpymem(p, h[i].key.data, h[i].key.len);
        }
    }
    components[0].len = p - components[0].data;
    ngx_qsort(cookies.elts, cookies.nelts, sizeof(ngx_ja4h_cookie_t),
              ngx_ja4h_cookie_compare);
    cookie = cookies.elts;
    for (j = 1; j < 3; j++) {
        *p++ = '_';
        components[j].data = p;
        for (i = 0; i < cookies.nelts; i++) {
            if (i) {
                *p++ = ',';
            }
            p = ngx_cpymem(p, cookie[i].pair.data,
                          j == 1 ? cookie[i].name_len : cookie[i].pair.len);
        }
        components[j].len = p - components[j].data;
    }
    ctx->raw.len = p - ctx->raw.data;
    p = ngx_cpymem(ctx->hash.data, prefix, 12);
    for (i = 0; i < 3; i++) {
        *p++ = '_';
        if (ngx_ja4_hash(&components[i], p) != NGX_OK) {
            return NGX_ERROR;
        }
        p += 12;
    }
    ctx->hash.len = p - ctx->hash.data;
    ngx_http_set_ctx(r, ctx, ngx_http_ssl_fingerprint_module);
    *out = raw ? ctx->raw : ctx->hash;
    return NGX_OK;
}

#if (NGX_HAVE_TCP_SAVE_SYN)

#define NGX_HTTP_JA4T_MAX_KINDS  40

typedef struct {
    unsigned int     window_size;
    unsigned char    kinds[NGX_HTTP_JA4T_MAX_KINDS];
    size_t           nkinds;
    unsigned int     mss;
    unsigned int     mss_present;
    unsigned int     window_scale;
    unsigned int     wscale_present;
} ngx_http_ja4t_t;


static ngx_int_t
ngx_ja4t_parse_syn(const u_char *buf, size_t len, ngx_http_ja4t_t *ja4t)
{
    size_t        off, tcp_off, tcp_hlen, remaining, adv;
    const u_char *tcp, *opt, *opt_end;
    u_char        kind, olen, ver, nxt, seen_eol;

    if (buf == NULL || len < 20) {
        return NGX_DECLINED;
    }

    ngx_memset(ja4t, 0, sizeof(ngx_http_ja4t_t));

    ver = buf[0] >> 4;

    if (ver == 4) {
        off = (buf[0] & 0x0f) * 4;
        if (off < 20 || off + 20 > len || buf[9] != IPPROTO_TCP
            || (buf[6] & 0x3f) != 0 || buf[7] != 0) {
            return NGX_DECLINED;
        }

        tcp_off = off;

    } else if (ver == 6) {
        if (len < 40) {
            return NGX_DECLINED;
        }

        nxt = buf[6];
        off = 40;

        while (nxt != IPPROTO_TCP) {
            if (off + 2 > len) {
                return NGX_DECLINED;
            }

            switch (nxt) {
            case IPPROTO_HOPOPTS:
            case IPPROTO_ROUTING:
            case IPPROTO_DSTOPTS:
                adv = ((size_t) buf[off + 1] + 1) * 8;
                nxt = buf[off];
                off += adv;
                break;

            case IPPROTO_FRAGMENT:
                if (off + 8 > len || buf[off + 2] != 0
                    || (buf[off + 3] & 0xf9) != 0)
                {
                    return NGX_DECLINED;
                }
                nxt = buf[off];
                off += 8;
                adv = 8;
                break;

            case IPPROTO_AH:
                adv = ((size_t) buf[off + 1] + 2) * 4;
                nxt = buf[off];
                off += adv;
                break;

            default:
                return NGX_DECLINED;
            }

            /* every extension header advances by at least 8 bytes */
            if (adv < 8 || off + 20 > len) {
                return NGX_DECLINED;
            }
        }

        tcp_off = off;

    } else {
        return NGX_DECLINED;
    }

    if (tcp_off + 20 > len) {
        return NGX_DECLINED;
    }

    tcp = buf + tcp_off;
    tcp_hlen = ((tcp[12] >> 4) & 0x0f) * 4;
    if (tcp_hlen < 20 || tcp_off + tcp_hlen > len
        || (tcp[13] & 0x12) != 0x02) {
        return NGX_DECLINED;
    }

    ja4t->window_size = ((unsigned int) tcp[14] << 8) | tcp[15];

    opt = tcp + 20;
    opt_end = tcp + tcp_hlen;
    seen_eol = 0;

    while (opt < opt_end) {
        remaining = (size_t) (opt_end - opt);
        kind = opt[0];

        if (ja4t->nkinds >= NGX_HTTP_JA4T_MAX_KINDS) {
            return NGX_DECLINED;
        }

        ja4t->kinds[ja4t->nkinds++] = kind;

        if (kind == 0) {
            seen_eol = 1;

            opt++;
            continue;
        }

        if (kind == 1) {
            opt++;
            continue;
        }

        if (remaining < 2) {
            return NGX_DECLINED;
        }

        olen = opt[1];
        if (olen < 2 || olen > remaining) {
            return NGX_DECLINED;
        }

        /* kinds after EOL stay in the list; MSS / window scale do not */
        if (!seen_eol && kind == 2 && olen == 4) {
            ja4t->mss = ((unsigned int) opt[2] << 8) | opt[3];
            ja4t->mss_present = 1;
        }

        if (!seen_eol && kind == 3 && olen == 3) {
            ja4t->window_scale = opt[2];
            ja4t->wscale_present = 1;
        }

        opt += olen;
    }

    return NGX_OK;
}


ngx_int_t
ngx_tcp_ja4t(ngx_connection_t *c, ngx_str_t *out)
{
    ngx_http_ja4t_t  ja4t;
    u_char          *p, *last;
    size_t           i, size;

    out->data = NULL;
    out->len = 0;

    if (c == NULL || c->pool == NULL || c->type != SOCK_STREAM) {
        return NGX_DECLINED;
    }

#if (NGX_QUIC || NGX_COMPAT)
    if (c->quic) {
        return NGX_DECLINED;
    }
#endif

    if (c->ja4t.data != NULL) {
        *out = c->ja4t;
        return NGX_OK;
    }

    if (c->saved_syn.len < 20 || c->saved_syn.data == NULL) {
        return NGX_DECLINED;
    }

    if (ngx_ja4t_parse_syn(c->saved_syn.data, c->saved_syn.len, &ja4t)
        != NGX_OK)
    {
        return NGX_DECLINED;
    }

    /*
     * worst case: window_size(5) + "_" + kinds(each up to 3 digits plus a
     * separator) + "_" + mss(5) + "_" + wscale(3) + margin.
     */
    size = 32 + (size_t) NGX_HTTP_JA4T_MAX_KINDS * 4;

    out->data = ngx_pnalloc(c->pool, size);
    if (out->data == NULL) {
        return NGX_ERROR;
    }

    p = out->data;
    last = out->data + size;

#define NGX_JA4T_NEED(n)                                                       \
    if ((size_t) (last - p) < (size_t) (n)) {                                  \
        out->data = NULL;                                                      \
        out->len = 0;                                                          \
        return NGX_DECLINED;                                                   \
    }

    NGX_JA4T_NEED(6);
    p = ngx_sprintf(p, "%uD", ja4t.window_size);
    *p++ = '_';

    if (ja4t.nkinds == 0) {
        NGX_JA4T_NEED(2);
        *p++ = '0';
        *p++ = '0';
    } else {
        for (i = 0; i < ja4t.nkinds; i++) {
            NGX_JA4T_NEED(5);
            if (i > 0) {
                *p++ = '-';
            }

            p = ngx_sprintf(p, "%ud", (unsigned) ja4t.kinds[i]);
        }
    }

    NGX_JA4T_NEED(1);
    *p++ = '_';

    if (ja4t.mss_present) {
        NGX_JA4T_NEED(6);
        p = ngx_sprintf(p, "%02uD", ja4t.mss);
    } else {
        NGX_JA4T_NEED(2);
        *p++ = '0';
        *p++ = '0';
    }

    NGX_JA4T_NEED(1);
    *p++ = '_';

    if (ja4t.wscale_present && ja4t.window_scale != 0) {
        NGX_JA4T_NEED(4);
        p = ngx_sprintf(p, "%uD", ja4t.window_scale);
    } else {
        NGX_JA4T_NEED(2);
        *p++ = '0';
        *p++ = '0';
    }

#undef NGX_JA4T_NEED

    out->len = p - out->data;

    c->ja4t = *out;

    return NGX_OK;
}


#else

ngx_int_t
ngx_tcp_ja4t(ngx_connection_t *c, ngx_str_t *out)
{
    return NGX_DECLINED;
}

#endif
