
/*
 * Obj: nginx_ssl_fingerprint.c
 */

#ifndef NGINX_SSL_FINGERPRINT_H_
#define NGINX_SSL_FINGERPRINT_H_ 1


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_SSL_FP_POOL(c)  ((c)->ssl->fp_pool ? (c)->ssl->fp_pool : (c)->pool)

ngx_int_t ngx_ssl_client_hello_get_ja_data(ngx_ssl_conn_t *ssl,
    ngx_pool_t *pool, ngx_str_t *out, uint32_t *alpn_offset);
int ngx_ssl_ja3(ngx_connection_t *c);
int ngx_ssl_ja3_hash(ngx_connection_t *c);
int ngx_ssl_ja4(ngx_connection_t *c);
ngx_int_t ngx_ssl_client_alpn(ngx_connection_t *c, ngx_str_t *out);
ngx_int_t ngx_ssl_quic_transport_params(ngx_connection_t *c, ngx_str_t *out);
ngx_int_t ngx_ssl_quic_transport_params_normalized(ngx_connection_t *c,
    ngx_str_t *out);
ngx_int_t ngx_ssl_quic_transport_params_raw(ngx_connection_t *c,
    ngx_str_t *out);
void ngx_ssl_quic_vn_record(ngx_connection_t *c, uint32_t version);
ngx_flag_t ngx_ssl_quic_vn_match(ngx_connection_t *c, uint32_t *version);
int ngx_http2_fingerprint(ngx_http_request_t *r, ngx_str_t *out);
#if (NGX_HTTP_V3)
int ngx_http3_settings(ngx_http_request_t *r, ngx_str_t *out);
int ngx_http3_qpack(ngx_http_request_t *r, ngx_str_t *out);
int ngx_http3_fingerprint(ngx_http_request_t *r, ngx_str_t *out);
int ngx_http3_fingerprint_hash(ngx_http_request_t *r, ngx_str_t *out);
int ngx_http3_fingerprint_normalized(ngx_http_request_t *r, ngx_str_t *out);
int ngx_http3_fingerprint_hash_normalized(ngx_http_request_t *r,
    ngx_str_t *out);
#endif

#endif /** NGINX_SSL_FINGERPRINT_H_ */
