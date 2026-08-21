
/*
 * Obj: nginx_ssl_fingerprint.c
 */

#ifndef NGINX_SSL_FINGERPRINT_H_
#define NGINX_SSL_FINGERPRINT_H_ 1


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_SSL_FP_POOL(c)  ((c)->ssl->fp_pool ? (c)->ssl->fp_pool : (c)->pool)

size_t ngx_ssl_client_hello_get_ja_data(ngx_ssl_conn_t *ssl, u_char *data,
    size_t data_size);
int ngx_ssl_ja3(ngx_connection_t *c);
int ngx_ssl_ja3_hash(ngx_connection_t *c);
int ngx_ssl_ja4(ngx_connection_t *c);
int ngx_http2_fingerprint(ngx_http_request_t *r, ngx_str_t *out);

#endif /** NGINX_SSL_FINGERPRINT_H_ */
