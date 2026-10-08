
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#if (NGX_HTTP_V2)
#include <ngx_http_v2.h>
#endif

#include <nginx_ssl_fingerprint.h>

static ngx_int_t ngx_http_ssl_fingerprint_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_ja4plus_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_greased(ngx_http_request_t *r,
                            ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_ja3(ngx_http_request_t *r,
                            ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_ja3_hash(ngx_http_request_t *r,
                             ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_ja4(ngx_http_request_t *r,
                            ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_ja4_r(ngx_http_request_t *r,
                            ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_alpn(ngx_http_request_t *r,
                            ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_quic_scalar(ngx_http_request_t *r,
                            ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_quic_transport_parameters(ngx_http_request_t *r,
                            ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_http2_fingerprint(ngx_http_request_t *r,
                            ngx_http_variable_value_t *v, uintptr_t data);
#if (NGX_HTTP_V3)
static ngx_int_t ngx_http_http3_fingerprint_variable(ngx_http_request_t *r,
                            ngx_http_variable_value_t *v, uintptr_t data);
#endif

enum {
    NGX_HTTP_QUIC_VERSION = 0,
    NGX_HTTP_QUIC_INITIAL_PACKET_SIZE,
    NGX_HTTP_QUIC_DCID_LENGTH,
    NGX_HTTP_QUIC_SCID_LENGTH,
    NGX_HTTP_QUIC_RETRY,
    NGX_HTTP_QUIC_VERSION_NEGOTIATION
};

#if (NGX_HTTP_V3)
enum {
    NGX_HTTP3_SETTINGS = 0,
    NGX_HTTP3_QPACK,
    NGX_HTTP3_FINGERPRINT,
    NGX_HTTP3_FINGERPRINT_HASH,
    NGX_HTTP3_FINGERPRINT_NORMALIZED,
    NGX_HTTP3_FINGERPRINT_HASH_NORMALIZED
};
#endif

static ngx_http_module_t ngx_http_ssl_fingerprint_module_ctx = {
    ngx_http_ssl_fingerprint_init,  /* preconfiguration */
    NULL,                           /* postconfiguration */
    NULL,                           /* create main configuration */
    NULL,                           /* init main configuration */
    NULL,                           /* create server configuration */
    NULL,                           /* merge server configuration */
    NULL,                           /* create location configuration */
    NULL                            /* merge location configuration */
};

ngx_module_t ngx_http_ssl_fingerprint_module = {
    NGX_MODULE_V1,
    &ngx_http_ssl_fingerprint_module_ctx, /* module context */
    NULL,                                 /* module directives */
    NGX_HTTP_MODULE,                      /* module type */
    NULL,                                 /* init master */
    NULL,                                 /* init module */
    ngx_ja4l_init_process,                 /* init process */
    NULL,                                 /* init thread */
    NULL,                                 /* exit thread */
    ngx_ja4l_exit_process,                 /* exit process */
    NULL,                                 /* exit master */
    NGX_MODULE_V1_PADDING};

static ngx_http_variable_t ngx_http_ssl_fingerprint_variables_list[] = {
    {ngx_string("http_ssl_ja4h"), NULL, ngx_http_ja4plus_variable, 0, 0, 0},
    {ngx_string("http_ssl_ja4h_r"), NULL, ngx_http_ja4plus_variable, 1, 0, 0},
    {ngx_string("http_ssl_client_ja4x"), NULL, ngx_http_ja4plus_variable, 2, 0, 0},
    {ngx_string("http_ssl_client_ja4x_r"), NULL, ngx_http_ja4plus_variable, 3, 0, 0},
    {ngx_string("http_ssl_ja4t"), NULL, ngx_http_ja4plus_variable, 4, 0, 0},
    {ngx_string("http_ssl_ja4l"), NULL, ngx_http_ja4plus_variable,
     5, NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_string("http_ssl_ja4l_delta"), NULL, ngx_http_ja4plus_variable,
     6, NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_string("http_ssl_greased"), NULL, ngx_http_ssl_greased,
     0, 0, 0},
    {ngx_string("http_ssl_ja3"), NULL, ngx_http_ssl_ja3,
     0, 0, 0},
    {ngx_string("http_ssl_ja3_hash"), NULL, ngx_http_ssl_ja3_hash,
     0, 0, 0},
    {ngx_string("http_ssl_ja4"), NULL, ngx_http_ssl_ja4,
     0, 0, 0},
    {ngx_string("http_ssl_ja4_r"), NULL, ngx_http_ssl_ja4_r,
     0, 0, 0},
    {ngx_string("http_ssl_alpn"), NULL, ngx_http_ssl_alpn,
     0, 0, 0},
    {ngx_string("quic_version"), NULL, ngx_http_quic_scalar,
     NGX_HTTP_QUIC_VERSION, 0, 0},
    {ngx_string("quic_initial_packet_size"), NULL, ngx_http_quic_scalar,
     NGX_HTTP_QUIC_INITIAL_PACKET_SIZE, 0, 0},
    {ngx_string("quic_dcid_length"), NULL, ngx_http_quic_scalar,
     NGX_HTTP_QUIC_DCID_LENGTH, 0, 0},
    {ngx_string("quic_scid_length"), NULL, ngx_http_quic_scalar,
     NGX_HTTP_QUIC_SCID_LENGTH, 0, 0},
    {ngx_string("quic_retry"), NULL, ngx_http_quic_scalar,
     NGX_HTTP_QUIC_RETRY, 0, 0},
    {ngx_string("quic_version_negotiation"), NULL, ngx_http_quic_scalar,
     NGX_HTTP_QUIC_VERSION_NEGOTIATION, 0, 0},
    {ngx_string("quic_transport_parameters"), NULL,
     ngx_http_quic_transport_parameters, 0, 0, 0},
    {ngx_string("quic_transport_parameters_raw"), NULL,
     ngx_http_quic_transport_parameters, 1, 0, 0},
    {ngx_string("quic_transport_parameters_normalized"), NULL,
     ngx_http_quic_transport_parameters, 2, 0, 0},
    {ngx_string("http2_fingerprint"), NULL, ngx_http_http2_fingerprint,
     0, 0, 0},
#if (NGX_HTTP_V3)
    {ngx_string("http3_settings"), NULL, ngx_http_http3_fingerprint_variable,
     NGX_HTTP3_SETTINGS, NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_string("http3_qpack"), NULL, ngx_http_http3_fingerprint_variable,
     NGX_HTTP3_QPACK, NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_string("http3_fingerprint"), NULL,
     ngx_http_http3_fingerprint_variable,
     NGX_HTTP3_FINGERPRINT, NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_string("http3_fingerprint_hash"), NULL,
     ngx_http_http3_fingerprint_variable,
     NGX_HTTP3_FINGERPRINT_HASH, NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_string("http3_perk"), NULL, ngx_http_http3_fingerprint_variable,
     NGX_HTTP3_FINGERPRINT, NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_string("http3_perk_hash"), NULL,
     ngx_http_http3_fingerprint_variable,
     NGX_HTTP3_FINGERPRINT_HASH, NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_string("http3_perk_normalized"), NULL,
     ngx_http_http3_fingerprint_variable,
     NGX_HTTP3_FINGERPRINT_NORMALIZED, NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_string("http3_perk_hash_normalized"), NULL,
     ngx_http_http3_fingerprint_variable,
     NGX_HTTP3_FINGERPRINT_HASH_NORMALIZED, NGX_HTTP_VAR_NOCACHEABLE, 0},
#endif
    ngx_http_null_variable
};

static ngx_int_t
ngx_http_ja4plus_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_int_t         rc;
    ngx_str_t         fp;
    ngx_connection_t *c;

    v->not_found = 1;
    c = r->connection;
#if (NGX_HTTP_V2)
    if (r->stream) {
        c = r->stream->connection->connection;
    }
#endif
    if (data < 2) {
        rc = ngx_http_ja4h(r, &fp, data);
    } else if (data < 4) {
        rc = ngx_ssl_client_ja4x(c, &fp, data - 2);
    } else if (data == 4) {
        rc = ngx_tcp_ja4t(c, &fp);
    } else {
        rc = ngx_ja4l(c, &fp, data - 5,
                     c->ssl == NULL && r->http_version < NGX_HTTP_VERSION_20);
    }
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }
    if (rc == NGX_OK) {
        v->data = fp.data;
        v->len = fp.len;
        v->valid = 1;
        v->not_found = 0;
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_ssl_greased(ngx_http_request_t *r,
                 ngx_http_variable_value_t *v, uintptr_t data)
{
    /* For access.log's map $http2_VAR {}:
     * if it's not found, then user could add a defined string */
    v->not_found = 1;

    if (r->connection->ssl == NULL) {
        return NGX_OK;
    }

    if (r->connection->ssl->fp_ja3_str.data == NULL
        && ngx_ssl_ja3(r->connection) != NGX_OK)
    {
        return NGX_OK;
    }

    v->len = 1;
    v->data = (u_char*) (r->connection->ssl->fp_tls_greased ? "1" : "0");
    v->not_found = 0;
    v->valid = 1;

    return NGX_OK;
}

static ngx_int_t
ngx_http_ssl_ja3(ngx_http_request_t *r,
                 ngx_http_variable_value_t *v, uintptr_t data)
{
    /* For access.log's map $VAR {}:
     * if it's not found, then user could add a defined string */
    v->not_found = 1;

    if (r->connection->ssl == NULL) {
        return NGX_OK;
    }

    if (r->connection->ssl->fp_ja3_str.data == NULL
        && ngx_ssl_ja3(r->connection) != NGX_OK)
    {
        return NGX_OK;
    }

    v->data = r->connection->ssl->fp_ja3_str.data;
    v->len = r->connection->ssl->fp_ja3_str.len;
    v->not_found = 0;
    v->valid = 1;

    return NGX_OK;
}

static ngx_int_t
ngx_http_ssl_ja3_hash(ngx_http_request_t *r,
                 ngx_http_variable_value_t *v, uintptr_t data)
{
    /* For access.log's map $VAR {}:
     * if it's not found, then user could add a defined string */
    v->not_found = 1;

    if (r->connection->ssl == NULL) {
        return NGX_OK;
    }

    if (r->connection->ssl->fp_ja3_hash.data == NULL
        && ngx_ssl_ja3_hash(r->connection) != NGX_OK)
    {
        return NGX_OK;
    }

    v->data = r->connection->ssl->fp_ja3_hash.data;
    v->len = r->connection->ssl->fp_ja3_hash.len;
    v->not_found = 0;
    v->valid = 1;

    return NGX_OK;
}

static ngx_int_t
ngx_http_ssl_ja4(ngx_http_request_t *r,
                 ngx_http_variable_value_t *v, uintptr_t data)
{
    /* For access.log's map $VAR {}:
     * if it's not found, then user could add a defined string */
    v->not_found = 1;

    if (r->connection->ssl == NULL) {
        return NGX_OK;
    }

    if (r->connection->ssl->fp_ja4_str.data == NULL
        && ngx_ssl_ja4(r->connection) != NGX_OK)
    {
        return NGX_OK;
    }

    v->data = r->connection->ssl->fp_ja4_str.data;
    v->len = r->connection->ssl->fp_ja4_str.len;
    v->not_found = 0;
    v->valid = 1;

    return NGX_OK;
}

static ngx_int_t
ngx_http_ssl_ja4_r(ngx_http_request_t *r,
                   ngx_http_variable_value_t *v, uintptr_t data)
{
    v->not_found = 1;

    if (r->connection->ssl == NULL) {
        return NGX_OK;
    }

    if (r->connection->ssl->fp_ja4_r_str.data == NULL
        && ngx_ssl_ja4(r->connection) != NGX_OK)
    {
        return NGX_OK;
    }

    v->data = r->connection->ssl->fp_ja4_r_str.data;
    v->len = r->connection->ssl->fp_ja4_r_str.len;
    v->not_found = 0;
    v->valid = 1;

    return NGX_OK;
}

static ngx_int_t
ngx_http_ssl_alpn(ngx_http_request_t *r,
                  ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t  alpn;

    v->not_found = 1;

    if (r->connection->ssl == NULL
        || ngx_ssl_client_alpn(r->connection, &alpn) != NGX_OK)
    {
        return NGX_OK;
    }

    v->data = alpn.data;
    v->len = alpn.len;
    v->not_found = 0;
    v->valid = 1;

    return NGX_OK;
}

static u_char *
ngx_http_quic_version_hex(u_char *p, uint32_t version)
{
    static const u_char  hex[] = "0123456789abcdef";
    ngx_uint_t           i;

    for (i = 0; i < 8; i++) {
        *p++ = hex[(version >> (28 - i * 4)) & 0x0f];
    }

    return p;
}

static u_char  ngx_http_quic_v1[] = "00000001";
static u_char  ngx_http_quic_v2[] = "6b3343cf";
static u_char  ngx_http_quic_min_initial[] = "1200";
static u_char  ngx_http_quic_digits[] = "0123456789";
static u_char  ngx_http_quic_cid_lengths[] = "1011121314151617181920";

static ngx_int_t
ngx_http_quic_scalar(ngx_http_request_t *r,
                     ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                       *p;
    size_t                        value;
    ngx_ssl_fingerprint_extra_t  *fp;

    v->not_found = 1;

    if (r->connection->ssl == NULL || r->connection->ssl->fp_extra == NULL)
    {
        return NGX_OK;
    }
    fp = r->connection->ssl->fp_extra;
    if (fp->quic_version == 0) {
        return NGX_OK;
    }

    switch (data) {
    case NGX_HTTP_QUIC_VERSION:
        v->len = 8;
        if (fp->quic_version == 0x00000001) {
            v->data = ngx_http_quic_v1;
            break;
        }
        if (fp->quic_version == 0x6b3343cf) {
            v->data = ngx_http_quic_v2;
            break;
        }
        v->data = ngx_pnalloc(r->pool, v->len);
        if (v->data == NULL) {
            return NGX_OK;
        }
        (void) ngx_http_quic_version_hex(v->data,
                                         fp->quic_version);
        break;

    case NGX_HTTP_QUIC_INITIAL_PACKET_SIZE:
        value = fp->quic_initial_packet_size;
        if (value == 1200) {
            v->data = ngx_http_quic_min_initial;
            v->len = 4;
            break;
        }
        goto decimal;

    case NGX_HTTP_QUIC_DCID_LENGTH:
        value = fp->quic_dcid_length;
        goto cid_length;

    case NGX_HTTP_QUIC_SCID_LENGTH:
        value = fp->quic_scid_length;
        goto cid_length;

    case NGX_HTTP_QUIC_RETRY:
        v->len = 1;
        v->data = (u_char *) (fp->quic_retry ? "1" : "0");
        break;

    default: /* NGX_HTTP_QUIC_VERSION_NEGOTIATION */
        if (!fp->quic_version_negotiated) {
            v->len = 1;
            v->data = (u_char *) "0";
            break;
        }

        v->len = 17;
        v->data = ngx_pnalloc(r->pool, v->len);
        if (v->data == NULL) {
            return NGX_OK;
        }
        p = ngx_http_quic_version_hex(
            v->data, fp->quic_original_version);
        *p++ = '>';
        (void) ngx_http_quic_version_hex(
            p, fp->quic_version);
        break;
    }

    v->not_found = 0;
    v->valid = 1;
    return NGX_OK;

cid_length:

    if (value < 10) {
        v->data = ngx_http_quic_digits + value;
        v->len = 1;
    } else if (value <= 20) {
        v->data = ngx_http_quic_cid_lengths + (value - 10) * 2;
        v->len = 2;
    } else {
        goto decimal;
    }
    v->not_found = 0;
    v->valid = 1;
    return NGX_OK;

decimal:

    v->data = ngx_pnalloc(r->pool, NGX_INT64_LEN);
    if (v->data == NULL) {
        return NGX_OK;
    }
    p = ngx_sprintf(v->data, "%uz", value);
    v->len = p - v->data;
    v->not_found = 0;
    v->valid = 1;
    return NGX_OK;
}

static ngx_int_t
ngx_http_quic_transport_parameters(ngx_http_request_t *r,
                                   ngx_http_variable_value_t *v,
                                   uintptr_t data)
{
    ngx_str_t  params;
    ngx_int_t  rc;

    v->not_found = 1;

    if (r->connection->ssl == NULL || r->connection->ssl->fp_extra == NULL
        || r->connection->ssl->fp_extra->quic_version == 0)
    {
        return NGX_OK;
    }

    if (data == 1) {
        rc = ngx_ssl_quic_transport_params_raw(r->connection, &params);
    } else if (data == 2) {
        rc = ngx_ssl_quic_transport_params_normalized(r->connection, &params);
    } else {
        rc = ngx_ssl_quic_transport_params(r->connection, &params);
    }
    if (rc != NGX_OK) {
        return NGX_OK;
    }

    v->data = params.data;
    v->len = params.len;
    v->not_found = 0;
    v->valid = 1;

    return NGX_OK;
}

static ngx_int_t
ngx_http_http2_fingerprint(ngx_http_request_t *r,
                 ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t  fp;

    /* For access.log's map $VAR {}:
     * if it's not found, then user could add a defined string */
    v->not_found = 1;

    if (r->stream == NULL) {
        return NGX_OK;
    }

    if (ngx_http2_fingerprint(r, &fp)
            != NGX_OK)
    {
        return NGX_OK;
    }

    v->data = fp.data;
    v->len = fp.len;
    v->not_found = 0;
    v->valid = 1;

    return NGX_OK;
}

#if (NGX_HTTP_V3)

static ngx_int_t
ngx_http_http3_fingerprint_variable(ngx_http_request_t *r,
                                    ngx_http_variable_value_t *v,
                                    uintptr_t data)
{
    ngx_int_t  rc;
    ngx_str_t  fp;

    v->not_found = 1;

    switch (data) {
    case NGX_HTTP3_SETTINGS:
        rc = ngx_http3_settings(r, &fp);
        break;
    case NGX_HTTP3_QPACK:
        rc = ngx_http3_qpack(r, &fp);
        break;
    case NGX_HTTP3_FINGERPRINT:
        rc = ngx_http3_fingerprint(r, &fp);
        break;
    case NGX_HTTP3_FINGERPRINT_HASH:
        rc = ngx_http3_fingerprint_hash(r, &fp);
        break;
    case NGX_HTTP3_FINGERPRINT_NORMALIZED:
        rc = ngx_http3_fingerprint_normalized(r, &fp);
        break;
    default:
        rc = ngx_http3_fingerprint_hash_normalized(r, &fp);
        break;
    }

    if (rc != NGX_OK) {
        return NGX_OK;
    }

    v->data = fp.data;
    v->len = fp.len;
    v->not_found = 0;
    v->valid = 1;

    return NGX_OK;
}

#endif

static ngx_int_t
ngx_http_ssl_fingerprint_init(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_ssl_fingerprint_variables_list; v->name.len; v++) {

        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }
        /** NOTE: update it, if set_handler will be needed */
        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}
