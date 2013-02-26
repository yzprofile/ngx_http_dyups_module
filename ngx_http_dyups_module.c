#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_DYUPS_DELETING     1
#define NGX_DYUPS_DELETED      2

#define NGX_DYUPS_SHM_NAME_LEN 256

#define NGX_DYUPS_DELETE       1
#define NGX_DYUPS_ADD          2

#define ngx_dyups_add_timer(ev, timeout)                                      \
    if (!ngx_exiting && !ngx_quit) ngx_add_timer(ev, (timeout))


typedef struct {
    ngx_uint_t                    *count;
    ngx_flag_t                     dynamic;
    ngx_uint_t                     deleted;
    ngx_pool_t                    *pool;
    ngx_http_upstream_srv_conf_t  *upstream;
} ngx_http_dyups_srv_conf_t;


typedef struct {
    ngx_flag_t                     enable;
    ngx_array_t                    dy_upstreams;/* ngx_http_dyups_srv_conf_t */
    ngx_str_t                      shm_name;
    ngx_uint_t                     shm_size;
    ngx_msec_t                     read_msg_timeout;
} ngx_http_dyups_main_conf_t;


typedef struct {
    ngx_uint_t                           count;
    ngx_http_upstream_init_peer_pt       init;
} ngx_http_dyups_upstream_srv_conf_t;


typedef struct {
    void                                *data;
    ngx_http_dyups_upstream_srv_conf_t  *scf;
    ngx_event_get_peer_pt                get;
    ngx_event_free_peer_pt               free;
} ngx_http_dyups_ctx_t;


typedef struct ngx_dyups_shctx_s {
    ngx_queue_t                          msg_queue;
    /* status ? */
} ngx_dyups_shctx_t;


typedef struct ngx_dyups_global_ctx_s {
    ngx_event_t                          msg_timer;
    ngx_slab_pool_t                     *shpool;
    ngx_dyups_shctx_t                   *sh;
} ngx_dyups_global_ctx_t;


typedef struct ngx_dyups_msg_s {
    ngx_queue_t                          queue;
    ngx_str_t                            path;
    ngx_str_t                            content;
    ngx_int_t                            count;
    ngx_uint_t                           flag;
    ngx_pid_t                           *pid;
} ngx_dyups_msg_t;


static ngx_int_t ngx_http_dyups_init(ngx_conf_t *cf);
static void *ngx_http_dyups_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_dyups_init_main_conf(ngx_conf_t *cf, void *conf);
static char *ngx_http_dyups_interface(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_dyups_interface_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dyups_interface_read_body(ngx_http_request_t *r);
static ngx_buf_t *ngx_http_dyups_read_body(ngx_http_request_t *r);
static ngx_buf_t *ngx_http_dyups_read_body_from_file(ngx_http_request_t *r);
static void ngx_http_dyups_body_handler(ngx_http_request_t *r);
static ngx_array_t *ngx_dyups_parse_content(ngx_pool_t *pool, ngx_buf_t *buf);
static ngx_int_t ngx_dyups_conf_read_token(ngx_pool_t *pool, ngx_buf_t *body,
    ngx_array_t *args);
static void ngx_http_dyups_send_response(ngx_http_request_t *r,
    ngx_int_t status, ngx_str_t *content);
static ngx_int_t ngx_http_dyups_do_get(ngx_http_request_t *r,
    ngx_array_t *resource);
static ngx_int_t ngx_http_dyups_do_delete(ngx_http_request_t *r,
    ngx_array_t *resource);
static ngx_int_t ngx_http_dyups_do_post(ngx_http_request_t *r,
    ngx_array_t *resource, ngx_array_t *arglist, ngx_str_t *rv);
static ngx_http_dyups_srv_conf_t *ngx_dyups_find_upstream(ngx_str_t *name,
    ngx_int_t *idx);
static ngx_int_t ngx_dyups_add_server(ngx_http_dyups_srv_conf_t *duscf,
    ngx_array_t *arglist);
static ngx_int_t ngx_dyups_init_upstream(ngx_http_dyups_srv_conf_t *duscf,
    ngx_str_t *name, ngx_uint_t index);
static ngx_int_t ngx_dyups_delete_upstream(ngx_http_dyups_srv_conf_t *duscf);
static ngx_int_t ngx_http_dyups_check_commands(ngx_array_t *arglist);
static ngx_int_t ngx_http_dyups_init_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static void *ngx_http_dyups_create_srv_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_dyups_get_peer(ngx_peer_connection_t *pc, void *data);
static void ngx_http_dyups_free_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state);
static ngx_buf_t *ngx_http_dyups_show_list(ngx_http_request_t *r);
static ngx_buf_t *ngx_http_dyups_show_detail(ngx_http_request_t *r);
static ngx_buf_t *ngx_http_dyups_show_upstream(ngx_http_request_t *r,
    ngx_http_dyups_srv_conf_t *duscf);
static ngx_int_t ngx_http_dyups_init_shm_zone(ngx_shm_zone_t *shm_zone,
    void *data);
static char *ngx_http_dyups_init_shm(ngx_conf_t *cf, void *conf);
static ngx_int_t ngx_http_dyups_get_shm_name(ngx_str_t *shm_name,
    ngx_pool_t *pool, ngx_uint_t generation);
static ngx_int_t ngx_http_dyups_init_process(ngx_cycle_t *cycle);
static void ngx_http_dyups_read_msg(ngx_event_t *ev);
static ngx_int_t ngx_http_dyups_send_msg(ngx_str_t *path, ngx_buf_t *body,
    ngx_uint_t flag);
static void ngx_dyups_destroy_msg(ngx_slab_pool_t *shpool,
    ngx_dyups_msg_t *msg);
ngx_int_t ngx_dyups_sync_cmd(ngx_pool_t *pool, ngx_str_t *path,
    ngx_str_t *content, ngx_uint_t flag);
static ngx_array_t *ngx_dyups_parse_path(ngx_pool_t *pool, ngx_str_t *path);
static ngx_int_t ngx_dyups_do_delete(ngx_str_t *name, ngx_str_t *rv);


static ngx_command_t  ngx_http_dyups_commands[] = {

    { ngx_string("dyups_interface"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_dyups_interface,
      0,
      0,
      NULL },

    { ngx_string("dyups_read_msg_timeout"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_conf_set_msec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_dyups_main_conf_t, read_msg_timeout),
      NULL },

    { ngx_string("dyups_shm_zone_size"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_dyups_main_conf_t, shm_size),
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_dyups_module_ctx = {
    NULL,                             /* preconfiguration */
    ngx_http_dyups_init,              /* postconfiguration */

    ngx_http_dyups_create_main_conf,  /* create main configuration */
    ngx_http_dyups_init_main_conf,    /* init main configuration */

    ngx_http_dyups_create_srv_conf,   /* create server configuration */
    NULL,                             /* merge server configuration */

    NULL,                             /* create location configuration */
    NULL                              /* merge location configuration */
};


ngx_module_t  ngx_http_dyups_module = {
    NGX_MODULE_V1,
    &ngx_http_dyups_module_ctx,    /* module context */
    ngx_http_dyups_commands,       /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    ngx_http_dyups_init_process,   /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_uint_t ngx_http_dyups_shm_generation = 0;
ngx_dyups_global_ctx_t ngx_dyups_global_ctx;


static char *
ngx_http_dyups_interface(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t    *clcf;
    ngx_http_dyups_main_conf_t  *dmcf;

    dmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_dyups_module);
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_dyups_interface_handler;
    dmcf->enable = 1;

    return NGX_CONF_OK;
}


static void *
ngx_http_dyups_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_dyups_main_conf_t  *dmcf;

    dmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dyups_main_conf_t));
    if (dmcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&dmcf->dy_upstreams, cf->pool, 4,
                       sizeof(ngx_http_dyups_srv_conf_t))
        != NGX_OK)
    {
        return NULL;
    }

    dmcf->enable = NGX_CONF_UNSET;
    dmcf->shm_size = NGX_CONF_UNSET_UINT;
    dmcf->read_msg_timeout = NGX_CONF_UNSET_MSEC;

    return dmcf;
}


static char *
ngx_http_dyups_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_dyups_main_conf_t  *dmcf = conf;

    dmcf->enable = dmcf->enable == NGX_CONF_UNSET ? 0 : 1;

    if (dmcf->read_msg_timeout) {
        dmcf->read_msg_timeout = 1000;
    }

    if (dmcf->shm_size == NGX_CONF_UNSET_UINT) {
        dmcf->shm_size = 2 * 1024 * 1024;
    }

    return ngx_http_dyups_init_shm(cf, conf);
}


static char *
ngx_http_dyups_init_shm(ngx_conf_t *cf, void *conf)
{
    ngx_http_dyups_main_conf_t *dmcf = conf;

    ngx_shm_zone_t  *shm_zone;

    ngx_http_dyups_shm_generation++;

    if (ngx_http_dyups_get_shm_name(&dmcf->shm_name, cf->pool,
                                     ngx_http_dyups_shm_generation)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &dmcf->shm_name, dmcf->shm_size,
                                     &ngx_http_dyups_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_log_error(NGX_LOG_DEBUG, cf->log, 0,
                  "[dyups] init shm:%V, size:%ui", &dmcf->shm_name,
                  dmcf->shm_size);

    shm_zone->data = cf->pool;
    shm_zone->init = ngx_http_dyups_init_shm_zone;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_dyups_get_shm_name(ngx_str_t *shm_name, ngx_pool_t *pool,
    ngx_uint_t generation)
{
    u_char  *last;

    shm_name->data = ngx_palloc(pool, NGX_DYUPS_SHM_NAME_LEN);
    if (shm_name->data == NULL) {
        return NGX_ERROR;
    }

    last = ngx_snprintf(shm_name->data, NGX_DYUPS_SHM_NAME_LEN, "%s#%ui",
                        "ngx_http_dyups_module", generation);

    shm_name->len = last - shm_name->data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_dyups_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_slab_pool_t    *shpool;
    ngx_dyups_shctx_t  *sh;

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    sh = ngx_slab_alloc(shpool, sizeof(ngx_dyups_shctx_t));
    if (sh == NULL) {
        return NGX_ERROR;
    }

    ngx_dyups_global_ctx.sh = sh;
    ngx_dyups_global_ctx.shpool = shpool;

    ngx_queue_init(&sh->msg_queue);

    return NGX_OK;
}


static void *
ngx_http_dyups_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_dyups_upstream_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dyups_upstream_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
      conf->init = NULL;
    */
    return conf;
}


static ngx_int_t
ngx_http_dyups_init(ngx_conf_t *cf)
{
    ngx_uint_t                      i;
    ngx_http_dyups_srv_conf_t      *duscf;
    ngx_http_dyups_main_conf_t     *dmcf;
    ngx_http_upstream_srv_conf_t  **uscfp, *uscf;
    ngx_http_upstream_main_conf_t  *umcf;

    dmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_dyups_module);
    umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);

    if (!dmcf->enable) {
        return NGX_OK;
    }

    uscfp = umcf->upstreams.elts;
    for (i = 0; i < umcf->upstreams.nelts; i++) {

        uscf = uscfp[i];

#if NGX_DEBUG
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "%ui: %V", i, &uscf->host);
#endif

        duscf = ngx_array_push(&dmcf->dy_upstreams);
        if (duscf == NULL) {
            return NGX_ERROR;
        }

        ngx_memzero(duscf, sizeof(ngx_http_dyups_srv_conf_t));

        duscf->pool = ngx_create_pool(128, cf->log);
        if (duscf->pool == NULL) {
            return NGX_ERROR;
        }

        duscf->upstream = uscfp[i];
        duscf->dynamic = (uscfp[i]->port == 0
                          && uscfp[i]->flags & NGX_HTTP_UPSTREAM_CREATE);
        duscf->deleted = 0;

    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_dyups_init_process(ngx_cycle_t *cycle)
{
    ngx_event_t                 *timer;
    ngx_http_dyups_main_conf_t  *dmcf;

    dmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_http_dyups_module);

    timer = &ngx_dyups_global_ctx.msg_timer;
    ngx_memzero(timer, sizeof(ngx_event_t));

    timer->handler = ngx_http_dyups_read_msg;
    timer->log = cycle->log;
    timer->data = dmcf;

    ngx_add_timer(timer, dmcf->read_msg_timeout);

    return NGX_OK;
}


static ngx_int_t
ngx_http_dyups_interface_handler(ngx_http_request_t *r)
{
    ngx_array_t                 *res;
    ngx_event_t                 *timer;
    ngx_http_dyups_main_conf_t  *dmcf;

    dmcf = ngx_http_get_module_main_conf(r, ngx_http_dyups_module);
    timer = &ngx_dyups_global_ctx.msg_timer;

    res = ngx_dyups_parse_path(r->pool, &r->uri);
    if (res == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_dyups_read_msg(timer);

    if (r->method == NGX_HTTP_GET) {
        return ngx_http_dyups_do_get(r, res);
    }

    if (r->method == NGX_HTTP_DELETE) {
        return ngx_http_dyups_do_delete(r, res);
    }

    return ngx_http_dyups_interface_read_body(r);
}


static ngx_int_t
ngx_http_dyups_do_get(ngx_http_request_t *r, ngx_array_t *resource)
{
    ngx_int_t                   rc, status, dumy;
    ngx_buf_t                  *buf;
    ngx_str_t                  *value;
    ngx_chain_t                 out;
    ngx_http_dyups_srv_conf_t  *duscf;

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    if (resource->nelts == 0) {
        return NGX_HTTP_NOT_FOUND;
    }

    buf = NULL;
    value = resource->elts;

    if (value[0].len == 4
        && ngx_strncasecmp(value[0].data, (u_char *) "list", 4) == 0)
    {
        buf = ngx_http_dyups_show_list(r);
        if (buf == NULL) {
            status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto finish;
        }
    }

    if (value[0].len == 6
        && ngx_strncasecmp(value[0].data, (u_char *) "detail", 6) == 0)
    {
        buf = ngx_http_dyups_show_detail(r);
        if (buf == NULL) {
            status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto finish;
        }
    }

    if (value[0].len == 8
        && ngx_strncasecmp(value[0].data, (u_char *) "upstream", 8) == 0)
    {
        if (resource->nelts != 2) {
            status = NGX_HTTP_NOT_FOUND;
            goto finish;
        }

        duscf = ngx_dyups_find_upstream(&value[1], &dumy);
        if (duscf == NULL || duscf->deleted) {
            status = NGX_HTTP_NOT_FOUND;
            goto finish;
        }

        buf = ngx_http_dyups_show_upstream(r, duscf);
        if (buf == NULL) {
            status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto finish;
        }
    }

    status = buf ? NGX_HTTP_OK : NGX_HTTP_NOT_FOUND;

finish:
    r->headers_out.status = status;

    if (status != NGX_HTTP_OK) {
        r->headers_out.content_length_n = 0;
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        return rc;
    }

    if (status != NGX_HTTP_OK) {
        return ngx_http_send_special(r, NGX_HTTP_FLUSH);
    }

    buf->last_buf = 1;
    out.buf = buf;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static ngx_buf_t *
ngx_http_dyups_show_list(ngx_http_request_t *r)
{
    ngx_uint_t                   i, len;
    ngx_str_t                    host;
    ngx_buf_t                   *buf;
    ngx_http_dyups_srv_conf_t   *duscfs, *duscf;
    ngx_http_dyups_main_conf_t  *dumcf;

    dumcf = ngx_http_get_module_main_conf(r, ngx_http_dyups_module);

    len = 0;
    duscfs = dumcf->dy_upstreams.elts;
    for (i = 0; i < dumcf->dy_upstreams.nelts; i++) {

        duscf = &duscfs[i];

        if (!duscf->dynamic) {
            continue;
        }

        if (duscf->deleted) {
            continue;
        }

        len += duscf->upstream->host.len + 1;
    }

    buf = ngx_create_temp_buf(r->pool, len);
    if (buf == NULL) {
        return NULL;
    }

    for (i = 0; i < dumcf->dy_upstreams.nelts; i++) {

        duscf = &duscfs[i];

        if (!duscf->dynamic) {
            continue;
        }

        if (duscf->deleted) {
            continue;
        }

        host = duscf->upstream->host;
        buf->last = ngx_sprintf(buf->last, "%V\n", &host);
    }

    return buf;
}


static ngx_buf_t *
ngx_http_dyups_show_detail(ngx_http_request_t *r)
{
    ngx_uint_t                   i, j, len;
    ngx_str_t                    host;
    ngx_buf_t                   *buf;
    ngx_http_dyups_srv_conf_t   *duscfs, *duscf;
    ngx_http_dyups_main_conf_t  *dumcf;
    ngx_http_upstream_server_t  *us;

    dumcf = ngx_http_get_module_main_conf(r, ngx_http_dyups_module);

    len = 0;
    duscfs = dumcf->dy_upstreams.elts;
    for (i = 0; i < dumcf->dy_upstreams.nelts; i++) {

        duscf = &duscfs[i];

        if (!duscf->dynamic) {
            continue;
        }

        if (duscf->deleted) {
            continue;
        }

        len += duscf->upstream->host.len + 1;

        for (j = 0; j < duscf->upstream->servers->nelts; j++) {
            len += sizeof("server ") + 81;
        }
    }

    buf = ngx_create_temp_buf(r->pool, len);
    if (buf == NULL) {
        return NULL;
    }

    for (i = 0; i < dumcf->dy_upstreams.nelts; i++) {

        duscf = &duscfs[i];

        if (!duscf->dynamic) {
            continue;
        }

        if (duscf->deleted) {
            continue;
        }

        host = duscf->upstream->host;
        buf->last = ngx_sprintf(buf->last, "%V\n", &host);

        us = duscf->upstream->servers->elts;
        for (j = 0; j < duscf->upstream->servers->nelts; j++) {
            buf->last = ngx_sprintf(buf->last, "server %V\n",
                                    &us[j].addrs->name);
        }
        buf->last = ngx_sprintf(buf->last, "\n");
    }

    return buf;
}


static ngx_buf_t *
ngx_http_dyups_show_upstream(ngx_http_request_t *r,
    ngx_http_dyups_srv_conf_t *duscf)
{
    ngx_uint_t                   i, len;
    ngx_buf_t                   *buf;
    ngx_http_upstream_server_t  *us;

    len = 0;
    for (i = 0; i < duscf->upstream->servers->nelts; i++) {
        len += sizeof("server ") + 81;
    }

    buf = ngx_create_temp_buf(r->pool, len);
    if (buf == NULL) {
        return NULL;
    }

    us = duscf->upstream->servers->elts;
    for (i = 0; i < duscf->upstream->servers->nelts; i++) {
        buf->last = ngx_sprintf(buf->last, "server %V\n",
                                &us[i].addrs->name);
    }

    return buf;
}


static ngx_int_t
ngx_dyups_do_delete(ngx_str_t *name, ngx_str_t *rv)
{
    ngx_int_t                   rc, dumy;
    ngx_http_dyups_srv_conf_t  *duscf;

    duscf = ngx_dyups_find_upstream(name, &dumy);

    if (duscf == NULL || duscf->deleted) {
        ngx_str_set(rv, "not found uptream");
        return NGX_HTTP_NOT_FOUND;
    }

    rc = ngx_dyups_delete_upstream(duscf);
    if (rc != NGX_OK) {
        ngx_str_set(rv, "failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_HTTP_OK;
}


static ngx_int_t
ngx_http_dyups_do_delete(ngx_http_request_t *r, ngx_array_t *resource)
{
    ngx_str_t                  *value, name, rv;
    ngx_int_t                   status, rc;
    ngx_buf_t                  *b;
    ngx_chain_t                 out;

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    if (resource->nelts != 2) {
        ngx_str_set(&rv, "not support this interface");
        status = NGX_HTTP_NOT_ALLOWED;
        goto finish;
    }

    value = resource->elts;

    if (value[0].len == 8
        && ngx_strncasecmp(value[0].data, (u_char *) "upstream", 8) != 0)
    {
        ngx_str_set(&rv, "not support this api");
        status = NGX_HTTP_NOT_ALLOWED;
        goto finish;
    }

    name = value[1];

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "[dyups] delete upstream name: %V", &name);

    status = ngx_dyups_do_delete(&name, &rv);
    if (status != NGX_HTTP_OK) {
        goto finish;
    }

    rc = ngx_http_dyups_send_msg(&r->uri, NULL, NGX_DYUPS_DELETE);
    if (rc != NGX_OK) {
        ngx_str_set(&rv, "alert: delte success but not sync to other process");
        status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_str_set(&rv, "success");
    status = NGX_HTTP_OK;

finish:

    r->headers_out.status = status;
    r->headers_out.content_length_n = rv.len;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        return rc;
    }

    if (rv.len == 0) {
        return ngx_http_send_special(r, NGX_HTTP_FLUSH);
    }

    b = ngx_create_temp_buf(r->pool, rv.len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->pos = rv.data;
    b->last = rv.data + rv.len;
    b->last_buf = 1;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static ngx_int_t
ngx_http_dyups_interface_read_body(ngx_http_request_t *r)
{
    ngx_int_t  rc;

    rc = ngx_http_read_client_request_body(r, ngx_http_dyups_body_handler);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static void
ngx_http_dyups_body_handler(ngx_http_request_t *r)
{
    ngx_str_t     rv;
    ngx_int_t     status;
    ngx_buf_t    *body;
    ngx_array_t  *arglist, *res;

    res = ngx_dyups_parse_path(r->pool, &r->uri);
    if (res == NULL) {
        ngx_str_set(&rv, "out of memory");
        status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto finish;
    }

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        status = NGX_HTTP_NO_CONTENT;
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "[dyups] interface no content");
        ngx_str_set(&rv, "no content\n");
        goto finish;
    }

    if (r->request_body->temp_file) {

        body = ngx_http_dyups_read_body_from_file(r);
    } else {

        body = ngx_http_dyups_read_body(r);
    }

    ngx_str_set(&rv, "");

    if (body == NULL) {
        status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        ngx_str_set(&rv, "out of memory\n");
        goto finish;
    }

    arglist = ngx_dyups_parse_content(r->pool, body);
    if (arglist == NULL) {
        status = NGX_HTTP_BAD_REQUEST;
        ngx_str_set(&rv, "parse body error\n");
        goto finish;
    }

    if (r->method == NGX_HTTP_POST) {

        status = ngx_http_dyups_do_post(r, res, arglist, &rv);

    } else {
        status = NGX_HTTP_NOT_ALLOWED;
    }

    if (status == NGX_HTTP_OK) {

        if (ngx_http_dyups_send_msg(&r->uri, body, NGX_DYUPS_ADD)) {
            ngx_str_set(&rv, "alert: update success "
                        "but not sync to other process");
            status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

finish:

    ngx_http_dyups_send_response(r, status, &rv);
}


static ngx_int_t
ngx_dyups_do_update(ngx_str_t *name, ngx_array_t *arglist, ngx_str_t *rv)
{
    ngx_int_t                       rc, idx;
    ngx_http_dyups_srv_conf_t      *duscf;
    ngx_http_dyups_main_conf_t     *dumcf;
    ngx_http_upstream_srv_conf_t  **uscfp;
    ngx_http_upstream_main_conf_t  *umcf;

    umcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_http_upstream_module);
    dumcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                                ngx_http_dyups_module);

    duscf = ngx_dyups_find_upstream(name, &idx);

    if (idx == -1) {
        /* need create a new upstream */

        duscf = ngx_array_push(&dumcf->dy_upstreams);
        if (duscf == NULL) {
            ngx_str_set(rv, "out of memory");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        uscfp = ngx_array_push(&umcf->upstreams);
        if (uscfp == NULL) {
            ngx_str_set(rv, "out of memory");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_memzero(duscf, sizeof(ngx_http_dyups_srv_conf_t));
        idx = umcf->upstreams.nelts - 1;
    }

    if (duscf->deleted) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "[dyups] upstream reuse");
        duscf->deleted = 0;
    }

    rc = ngx_dyups_init_upstream(duscf, name, idx);

    if (rc != NGX_OK) {
        ngx_str_set(rv, "failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* init upstream */

    rc = ngx_dyups_add_server(duscf, arglist);
    if (rc != NGX_OK) {
        ngx_str_set(rv, "failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_HTTP_OK;
}


/*
  url: /upstream
  body: server ip:port weight
 */
static ngx_int_t
ngx_http_dyups_do_post(ngx_http_request_t *r, ngx_array_t *resource,
    ngx_array_t *arglist, ngx_str_t *rv)
{
    ngx_int_t                       rc;
    ngx_str_t                      *value, name;

    if (resource->nelts != 2) {
        ngx_str_set(rv, "not support this interface");
        return NGX_HTTP_NOT_FOUND;
    }

    value = resource->elts;

    if (value[0].len == 8
        && ngx_strncasecmp(value[0].data, (u_char *) "upstream", 8) != 0)
    {
        ngx_str_set(rv, "not support this api");
        return NGX_HTTP_NOT_FOUND;
    }

    name = value[1];

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "[dyups] upstream name: %V", &name);

    rc = ngx_http_dyups_check_commands(arglist);
    if (rc != NGX_OK) {
        ngx_str_set(rv, "commands error");
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_dyups_do_update(&name, arglist, rv);
    if (rc != NGX_HTTP_OK) {
        return rc;
    }

    ngx_str_set(rv, "success");

    return NGX_HTTP_OK;
}


static ngx_int_t
ngx_dyups_add_server(ngx_http_dyups_srv_conf_t *duscf, ngx_array_t *arglist)
{
    ngx_url_t                            u;
    ngx_str_t                           *value;
    ngx_conf_t                           cf;
    ngx_uint_t                           i;
    ngx_array_t                         *line;
    ngx_http_upstream_init_pt            init;
    ngx_http_upstream_server_t          *us;
    ngx_http_upstream_srv_conf_t        *uscf;
    ngx_http_dyups_upstream_srv_conf_t  *dscf;

    uscf = duscf->upstream;

    if (uscf->servers == NULL) {
        uscf->servers = ngx_array_create(duscf->pool, 4,
                                         sizeof(ngx_http_upstream_server_t));
        if (uscf->servers == NULL) {
            return NGX_ERROR;
        }
    }

    line = arglist->elts;
    for (i = 0; i < arglist->nelts; i++) {
        value = line[i].elts;
        if (value[0].len == 6
            && ngx_strncasecmp(value[0].data, (u_char *) "server", 6) == 0)
        {

            us = ngx_array_push(uscf->servers);
            if (us == NULL) {
                return NGX_ERROR;
            }

            ngx_memzero(us, sizeof(ngx_http_upstream_server_t));

            u.url = value[1];
            u.default_port = 80;

            /* TODO: parse ip*/
            if (ngx_parse_url(duscf->pool, &u) != NGX_OK) {
                if (u.err) {
                    ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0,
                                  "[dyups] %s in upstream \"%V\"",
                                  u.err, &u.url);
                }

                return NGX_ERROR;
            }

            us->addrs = u.addrs;
            us->naddrs = u.naddrs;
            us->weight = 1;
            us->max_fails = 1;
            us->fail_timeout = 10;
        }
    }

    cf.pool = duscf->pool;
    cf.module_type = NGX_HTTP_MODULE;
    cf.cmd_type = NGX_HTTP_MAIN_CONF;
    cf.log = ngx_cycle->log;

    init = uscf->peer.init_upstream ? uscf->peer.init_upstream:
        ngx_http_upstream_init_round_robin;

    if (init(&cf, uscf) != NGX_OK) {
        return NGX_ERROR;
    }

    dscf = uscf->srv_conf[ngx_http_dyups_module.ctx_index];
    dscf->init = uscf->peer.init;

    uscf->peer.init = ngx_http_dyups_init_peer;

    return NGX_OK;
}


static ngx_http_dyups_srv_conf_t *
ngx_dyups_find_upstream(ngx_str_t *name, ngx_int_t *idx)
{
    ngx_uint_t                      i;
    ngx_http_dyups_srv_conf_t      *duscfs, *duscf, *duscf_del;
    ngx_http_dyups_main_conf_t     *dumcf;
    ngx_http_upstream_srv_conf_t   *uscf;
    ngx_http_upstream_main_conf_t  *umcf;

    umcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_http_upstream_module);
    dumcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                                ngx_http_dyups_module);
    *idx = -1;
    duscf_del = NULL;

    duscfs = dumcf->dy_upstreams.elts;
    for (i = 0; i < dumcf->dy_upstreams.nelts; i++) {

        duscf = &duscfs[i];
        if (!duscf->dynamic) {
            continue;
        }

        if (duscf->deleted == NGX_DYUPS_DELETING && *(duscf->count) == 0) {
            if (duscf->pool) {

                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                               "[dyups] free dynamic upstream");

                ngx_destroy_pool(duscf->pool);
                duscf->pool = NULL;
            }

            duscf->deleted = NGX_DYUPS_DELETED;
        }

        if (duscf->deleted == NGX_DYUPS_DELETED) {
            *idx = i;
            duscf_del = duscf;
            continue;
        }

        uscf = duscf->upstream;

        if (uscf->host.len != name->len
            || ngx_strncasecmp(uscf->host.data, name->data, uscf->host.len)
               != 0)
        {
            continue;
        }

        if (duscf->count != NULL && *(duscf->count) != 0) {
            (void) ngx_dyups_delete_upstream(duscf);
            continue;
        }

        *idx = i;

        return duscf;
    }

    return duscf_del;
}


static ngx_int_t
ngx_dyups_init_upstream(ngx_http_dyups_srv_conf_t *duscf, ngx_str_t *name,
    ngx_uint_t index)
{
    void                                *mconf;
    ngx_uint_t                           m;
    ngx_conf_t                           cf;
    ngx_http_module_t                   *module;
    ngx_http_conf_ctx_t                 *ctx;
    ngx_http_upstream_srv_conf_t        *uscf, **uscfp;
    ngx_http_upstream_main_conf_t       *umcf;
    ngx_http_dyups_upstream_srv_conf_t  *dscf;

    umcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_http_upstream_module);
    uscfp = umcf->upstreams.elts;

    if (duscf->pool) {
        ngx_destroy_pool(duscf->pool);
    }

    uscf = duscf->upstream;

    duscf->pool = ngx_create_pool(128, ngx_cycle->log);
    if (duscf->pool == NULL) {
        return NGX_ERROR;
    }

    uscf = ngx_pcalloc(duscf->pool, sizeof(ngx_http_upstream_srv_conf_t));
    if (uscf == NULL) {
        return NGX_ERROR;
    }

    uscf->flags = NGX_HTTP_UPSTREAM_CREATE
                 |NGX_HTTP_UPSTREAM_WEIGHT
                 |NGX_HTTP_UPSTREAM_MAX_FAILS
                 |NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
                 |NGX_HTTP_UPSTREAM_DOWN
                 |NGX_HTTP_UPSTREAM_BACKUP;

    uscf->host.data = ngx_pstrdup(duscf->pool, name);
    uscf->host.len = name->len;
    uscf->file_name = (u_char *) "dynamic_upstream";
    uscf->line = 0;
    uscf->port = 0;
    uscf->default_port = 0;

    uscfp[index] = uscf;

    duscf->dynamic = 1;
    duscf->upstream = uscf;

    cf.module_type = NGX_HTTP_MODULE;
    cf.cmd_type = NGX_HTTP_MAIN_CONF;
    cf.pool = duscf->pool;

    ctx = ngx_pcalloc(duscf->pool, sizeof(ngx_http_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->main_conf = ((ngx_http_conf_ctx_t *)
                      ngx_cycle->conf_ctx[ngx_http_module.index])->main_conf;

    ctx->srv_conf = ngx_pcalloc(cf.pool, sizeof(void *) * ngx_http_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_ERROR;
    }

    ctx->srv_conf[ngx_http_upstream_module.ctx_index] = uscf;
    uscf->srv_conf = ctx->srv_conf;

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        if (ngx_modules[m]->index == ngx_http_core_module.index) {
            continue;
        }

        module = ngx_modules[m]->ctx;

        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(&cf);
            if (mconf == NULL) {
                return NGX_ERROR;
            }

            ctx->srv_conf[ngx_modules[m]->ctx_index] = mconf;
        }
    }

    dscf = uscf->srv_conf[ngx_http_dyups_module.ctx_index];
    duscf->count = &dscf->count;

    return NGX_OK;
}


static ngx_int_t
ngx_dyups_delete_upstream(ngx_http_dyups_srv_conf_t *duscf)
{
    ngx_uint_t                     i;
    ngx_conf_t                     cf;
    ngx_http_upstream_init_pt      init;
    ngx_http_upstream_server_t    *us;
    ngx_http_upstream_srv_conf_t  *uscf;

    uscf = duscf->upstream;

    us = uscf->servers->elts;
    for (i = 0; i < uscf->servers->nelts; i++) {
        us[i].down = 1;
    }

    ngx_str_set(&uscf->host, "_dyups_upstream_down_host_");

    cf.pool = duscf->pool;
    cf.module_type = NGX_HTTP_MODULE;
    cf.cmd_type = NGX_HTTP_MAIN_CONF;
    cf.log = ngx_cycle->log;

    init = uscf->peer.init_upstream ? uscf->peer.init_upstream:
        ngx_http_upstream_init_round_robin;

    if (init(&cf, uscf) != NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                      "[dyups] delete upstream error when call init");
        return NGX_ERROR;
    }

    duscf->deleted = NGX_DYUPS_DELETING;

    return NGX_OK;
}


static void
ngx_http_dyups_send_response(ngx_http_request_t *r, ngx_int_t status,
    ngx_str_t *content)
{
    ngx_int_t    rc;
    ngx_buf_t   *b;
    ngx_chain_t  out;

    r->headers_out.status = status;
    r->headers_out.content_length_n = content->len;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        ngx_http_finalize_request(r, rc);
        return;
    }

    if (content->len == 0) {
        ngx_http_finalize_request(r, ngx_http_send_special(r, NGX_HTTP_FLUSH));
        return;
    }

    b = ngx_create_temp_buf(r->pool, content->len);
    if (b == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    b->pos = content->data;
    b->last = content->data + content->len;
    b->last_buf = 1;

    out.buf = b;
    out.next = NULL;

    ngx_http_finalize_request(r, ngx_http_output_filter(r, &out));
}


static ngx_int_t
ngx_http_dyups_check_commands(ngx_array_t *arglist)
{
    ngx_int_t     rc;
    ngx_url_t     u;
    ngx_str_t    *value;
    ngx_pool_t   *pool;
    ngx_uint_t    i;
    ngx_array_t  *line;

    pool = ngx_create_pool(128, ngx_cycle->log);
    if (pool == NULL) {
        return NGX_ERROR;
    }

    line = arglist->elts;
    for (i = 0; i < arglist->nelts; i++) {
        value = line[i].elts;

        /* TODO */

        if (line[i].nelts != 2) {
            rc = NGX_ERROR;
            goto finish;
        }

        if (value[0].len == 6 &&
            ngx_strncasecmp(value[0].data, (u_char *) "server", 6) != 0)
        {
            rc = NGX_ERROR;
            goto finish;
        }

        u.url = value[1];
        u.default_port = 80;

        if (ngx_parse_url(pool, &u) != NGX_OK) {

            if (u.err) {
                ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0,
                              "[dyups] %s in upstream \"%V\"", u.err, &u.url);
            }

            rc = NGX_ERROR;
            goto finish;
        }

    }

    rc = NGX_OK;

finish:
    ngx_destroy_pool(pool);

    return rc;
}


static ngx_array_t *
ngx_dyups_parse_content(ngx_pool_t *pool, ngx_buf_t *buf)
{
    ngx_int_t     rc;
    ngx_buf_t     body;
    ngx_log_t    *log;
    ngx_array_t  *args_list, *args;

    log = pool->log;
    args_list = ngx_array_create(pool, 1, sizeof(ngx_array_t));
    if (args_list == NULL) {
        return NULL;
    }

    body = *buf;

    for ( ;; ) {

        args = ngx_array_push(args_list);
        if (args == NULL) {
            return NULL;
        }

        rc = ngx_array_init(args, pool, 1, sizeof(ngx_str_t));
        if (rc != NGX_OK) {
            return NULL;
        }

        rc = ngx_dyups_conf_read_token(pool, &body, args);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pool->log, 0,
                       "[dyups] read token rc: %i", rc);

        if (rc == NGX_OK) {

#if NGX_DEBUG
            ngx_str_t  *arg;
            ngx_uint_t  i;

            arg = args->elts;
            for (i = 0; i < args->nelts; i++) {
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pool->log, 0,
                               "[dyups] arg[%i]:%V", i, &arg[i]);
            }
#endif
            continue;
        }

        if (rc == NGX_DONE) {
            break;
        }

        /* NGX_ERROR */

        return NULL;
    }

    args_list->nelts--;

    return args_list;
}


static ngx_int_t
ngx_dyups_conf_read_token(ngx_pool_t *pool, ngx_buf_t *body, ngx_array_t *args)
{
    u_char      ch, *start, *src, *dst;
    ngx_str_t  *word;
    ngx_uint_t  found, need_space, last_space, len;
    ngx_uint_t  quoted, d_quoted, s_quoted, sharp_comment;

    found = 0;
    need_space = 0;
    last_space = 1;
    quoted = 0;
    d_quoted = 0;
    s_quoted = 0;
    sharp_comment = 0;

    start = body->pos;

    for ( ;; ) {

        if (body->pos >= body->last) {
            if (args->nelts > 0 || !last_space) {
                ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                              "unexpected end of body content");
                return NGX_ERROR;
            }

            return NGX_DONE;
        }

        ch = *body->pos++;

        if (ch == LF) {
            sharp_comment = 0;
        }

        if (sharp_comment) {
            continue;
        }

        if (quoted) {
            quoted = 0;
            continue;
        }

        if (need_space) {
            if (ch == ' ' || ch == '\t' || ch == CR || ch == LF) {
                last_space = 1;
                need_space = 0;
                continue;
            }

            if (ch == ';') {
                return NGX_OK;
            }
        }

        if (last_space) {
            if (ch == ' ' || ch == '\t' || ch == CR || ch == LF) {
                continue;
            }

            start = body->pos - 1;

            switch (ch) {
            case ';':
                if (args->nelts == 0) {
                    ngx_log_error(NGX_LOG_ERR, pool->log, 0,
                                  "unexpected \"%c\"", ch);
                    return NGX_ERROR;
                }

                return NGX_OK;

            case '#':
                sharp_comment = 1;
                continue;

            case '\\':
                quoted = 1;
                last_space = 0;
                continue;

            case '"':
                start++;
                d_quoted = 1;
                last_space = 0;
                continue;

            case '\'':
                start++;
                s_quoted = 1;
                last_space = 0;
                continue;

            default:
                last_space = 0;
            }

        } else {

            if (ch == '\\') {
                quoted = 1;
                continue;
            }

            if (d_quoted) {
                if (ch == '"') {
                    d_quoted = 0;
                    need_space = 1;
                    found = 1;
                }

            } else if (s_quoted) {
                if (ch == '\'') {
                    s_quoted = 0;
                    need_space = 1;
                    found = 1;
                }

            } else if (ch == ' ' || ch == '\t' || ch == CR || ch == LF
                       || ch == ';')
            {
                last_space = 1;
                found = 1;
            }

            if (found) {
                word = ngx_array_push(args);
                if (word == NULL) {
                    return NGX_ERROR;
                }

                word->data = ngx_pnalloc(pool, body->pos - start + 1);
                if (word->data == NULL) {
                    return NGX_ERROR;
                }

                for (dst = word->data, src = start, len = 0;
                     src < body->pos - 1;
                     len++)
                {
                    if (*src == '\\') {
                        switch (src[1]) {
                        case '"':
                        case '\'':
                        case '\\':
                            src++;
                            break;

                        case 't':
                            *dst++ = '\t';
                            src += 2;
                            continue;

                        case 'r':
                            *dst++ = '\r';
                            src += 2;
                            continue;

                        case 'n':
                            *dst++ = '\n';
                            src += 2;
                            continue;
                        }

                    }
                    *dst++ = *src++;
                }
                *dst = '\0';
                word->len = len;

                if (ch == ';') {
                    return NGX_OK;
                }

                found = 0;
            }
        }

    }

}


static ngx_buf_t *
ngx_http_dyups_read_body(ngx_http_request_t *r)
{
    size_t        len;
    ngx_buf_t    *buf, *next, *body;
    ngx_chain_t  *cl;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "[dyups] interface read post body");

    cl = r->request_body->bufs;
    buf = cl->buf;

    if (cl->next == NULL) {

        return buf;

    } else {

        next = cl->next->buf;
        len = (buf->last - buf->pos) + (next->last - next->pos);

        body = ngx_create_temp_buf(r->pool, len);
        if (body == NULL) {
            return NULL;
        }

        body->last = ngx_cpymem(body->last, buf->pos, buf->last - buf->pos);
        body->last = ngx_cpymem(body->last, next->pos, next->last - next->pos);
    }

    return body;
}


static ngx_buf_t *
ngx_http_dyups_read_body_from_file(ngx_http_request_t *r)
{
    size_t        len;
    ssize_t       size;
    ngx_buf_t    *buf, *body;
    ngx_chain_t  *cl;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "[dyups] interface read post body from file");

    len = 0;
    cl = r->request_body->bufs;

    while (cl) {

        buf = cl->buf;

        if (buf->in_file) {
            len += buf->file_last - buf->file_pos;

        } else {
            len += buf->last - buf->pos;
        }

        cl = cl->next;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "[dyups] interface read post body file size %ui", len);

    body = ngx_create_temp_buf(r->pool, len);
    if (body == NULL) {
        return NULL;
    }

    cl = r->request_body->bufs;

    while (cl) {

        buf = cl->buf;

        if (buf->in_file) {

            size = ngx_read_file(buf->file, body->last,
                                 buf->file_last - buf->file_pos, buf->file_pos);

            if (size == NGX_ERROR) {
                return NULL;
            }

            body->last += size;

        } else {

            body->last = ngx_cpymem(body->last, buf->pos, buf->last - buf->pos);
        }

        cl = cl->next;
    }

    return body;
}


ngx_array_t *
ngx_dyups_parse_path(ngx_pool_t *pool, ngx_str_t *path)
{
    u_char       *p, *last, *end;
    ngx_str_t    *str;
    ngx_array_t  *array;

    array = ngx_array_create(pool, 8, sizeof(ngx_str_t));
    if (array == NULL) {
        return NULL;
    }

    p = path->data + 1;
    last = path->data + path->len;

    while(p < last) {
        end = ngx_strlchr(p, last, '/');
        str = ngx_array_push(array);

        if (str == NULL) {
            return NULL;
        }

        if (end) {
            str->data = p;
            str->len = end - p;

        } else {
            str->data = p;
            str->len = last - p;

        }

        p += str->len + 1;
    }

#if NGX_DEBUG
    ngx_str_t  *arg;
    ngx_uint_t  i;

    arg = array->elts;
    for (i = 0; i < array->nelts; i++) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "[dyups] res[%i]:%V", i, &arg[i]);
    }
#endif

    return array;
}


static ngx_int_t
ngx_http_dyups_init_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_int_t                            rc;
    ngx_http_dyups_ctx_t                *ctx;
    ngx_http_dyups_upstream_srv_conf_t  *dscf;

    dscf = us->srv_conf[ngx_http_dyups_module.ctx_index];

    rc = dscf->init(r, us);

    if (rc != NGX_OK) {
        return rc;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_dyups_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->scf = dscf;
    ctx->data = r->upstream->peer.data;
    ctx->get = r->upstream->peer.get;
    ctx->free = r->upstream->peer.free;

    r->upstream->peer.data = ctx;
    r->upstream->peer.get = ngx_http_dyups_get_peer;
    r->upstream->peer.free = ngx_http_dyups_free_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_http_dyups_get_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_dyups_ctx_t  *ctx = data;

    ctx->scf->count++;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "[dyups] dynamic upstream get handler count %i",
                   ctx->scf->count);

    return ctx->get(pc, ctx->data);
}


static void
ngx_http_dyups_free_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_http_dyups_ctx_t  *ctx = data;

    ctx->scf->count--;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "[dyups] dynamic upstream free handler count %i",
                   ctx->scf->count);

    ctx->free(pc, ctx->data, state);
}


static void
ngx_http_dyups_read_msg(ngx_event_t *ev)
{
    ngx_int_t                    i, rc;
    ngx_str_t                    path, content;
    ngx_uint_t                   n;
    ngx_pool_t                  *pool;
    ngx_queue_t                 *q, *t;
    ngx_array_t                  msgs;
    ngx_core_conf_t             *ccf;
    ngx_slab_pool_t             *shpool;
    ngx_dyups_msg_t             *msg, *tmsg;
    ngx_dyups_shctx_t           *sh;
    ngx_http_dyups_main_conf_t  *dmcf;

    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                           ngx_core_module);

    dmcf = ev->data;
    sh = ngx_dyups_global_ctx.sh;
    shpool = ngx_dyups_global_ctx.shpool;

    ngx_shmtx_lock(&shpool->mutex);

    if (ngx_queue_empty(&sh->msg_queue)) {
        ngx_shmtx_unlock(&shpool->mutex);
        ngx_dyups_add_timer(ev, dmcf->read_msg_timeout);
        return;
    }

    pool = ngx_create_pool(ngx_pagesize, ev->log);
    if (pool == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        ngx_dyups_add_timer(ev, dmcf->read_msg_timeout);
        return;
    }

    rc = ngx_array_init(&msgs, pool, 8, sizeof(ngx_dyups_msg_t));

    if (rc != NGX_OK) {
        goto failed;
    }


    for (q = ngx_queue_last(&sh->msg_queue);
         q != ngx_queue_sentinel(&sh->msg_queue);
         q = ngx_queue_prev(q))
    {
        msg = ngx_queue_data(q, ngx_dyups_msg_t, queue);


        if (msg->count == ccf->worker_processes) {
            t = ngx_queue_next(q); ngx_queue_remove(q); q = t;

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                                  "[dyups] destroy msg %V:%V",
                                  &msg->path, &msg->content);

            ngx_dyups_destroy_msg(shpool, msg);
            continue;
        }

        for (i = 0; i < msg->count; i++) {
            if (msg->pid[i] == ngx_pid) {
                break;
            }
        }

        if (i != msg->count) {
            continue;
        }

        msg->pid[i] = ngx_pid;
        msg->count++;

        tmsg = ngx_array_push(&msgs);
        if (tmsg == NULL) {
            goto failed;
        }

        tmsg->flag = msg->flag;

        tmsg->path.data = ngx_pnalloc(pool, msg->path.len);
        if (tmsg->path.data == NULL) {
            goto failed;
        }

        ngx_memcpy(tmsg->path.data, msg->path.data, msg->path.len);
        tmsg->path.len = msg->path.len;

        tmsg->content.data = ngx_pnalloc(pool, msg->content.len);

        if (tmsg->content.data == NULL) {
            goto failed;
        }

        ngx_memcpy(tmsg->content.data, msg->content.data, msg->content.len);
        tmsg->content.len = msg->content.len;
    }

    ngx_shmtx_unlock(&shpool->mutex);

    msg = msgs.elts;
    for (n = 0; n < msgs.nelts; n++) {
        path = msg[n].path;
        content = msg[n].content;

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                       "[dyups] read msg path:%V, content:%V, flag %ui",
                       &path, &content, msg[n].flag);

        rc = ngx_dyups_sync_cmd(pool, &path, &content, msg[n].flag);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                          "[dyups] read msg error, may cause the "
                          "config inaccuracy, path:%V, content:%V",
                          &path, &content);
        }
    }

    ngx_destroy_pool(pool);

    ngx_dyups_add_timer(ev, dmcf->read_msg_timeout);

    return;

failed:
    ngx_log_error(NGX_LOG_ALERT, ev->log, 0, "[dyups] read msg error,"
                  "may cause the config inaccuracy");

    ngx_destroy_pool(pool);

    ngx_shmtx_unlock(&shpool->mutex);

    ngx_dyups_add_timer(ev, dmcf->read_msg_timeout);
}


static ngx_int_t
ngx_http_dyups_send_msg(ngx_str_t *path, ngx_buf_t *body, ngx_uint_t flag)
{
    ngx_core_conf_t    *ccf;
    ngx_slab_pool_t    *shpool;
    ngx_dyups_msg_t    *msg;
    ngx_dyups_shctx_t  *sh;

    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                           ngx_core_module);

    sh = ngx_dyups_global_ctx.sh;
    shpool = ngx_dyups_global_ctx.shpool;

    ngx_shmtx_lock(&shpool->mutex);

    msg = ngx_slab_alloc_locked(shpool, sizeof(ngx_dyups_msg_t));
    if (msg == NULL) {
        goto failed;
    }

    ngx_memzero(msg, sizeof(ngx_dyups_msg_t));

    msg->flag = flag;
    msg->count = 0;
    msg->pid = ngx_slab_alloc_locked(shpool, ccf->worker_processes);

    if (msg->pid == NULL) {
        goto failed;
    }

    ngx_memzero(msg->pid, sizeof(ngx_pid_t) * ccf->worker_processes);
    msg->pid[0] = ngx_pid;
    msg->count++;

    msg->path.data = ngx_slab_alloc_locked(shpool, path->len);
    if (msg->path.data == NULL) {
        goto failed;
    }

    ngx_memcpy(msg->path.data, path->data, path->len);
    msg->path.len = path->len;

    if (body) {
        msg->content.data = ngx_slab_alloc_locked(shpool,
                                                  body->last - body->pos);
        if (msg->content.data == NULL) {
            goto failed;
        }

        ngx_memcpy(msg->content.data, body->pos, body->last - body->pos);
        msg->content.len = body->last - body->pos;

    } else {
        msg->content.data = NULL;
        msg->content.len = 0;
    }

    ngx_queue_insert_head(&sh->msg_queue, &msg->queue);

    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;

failed:

    if (msg) {
        ngx_dyups_destroy_msg(shpool, msg);
    }

    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_ERROR;
}


static void
ngx_dyups_destroy_msg(ngx_slab_pool_t *shpool, ngx_dyups_msg_t *msg)
{
    if (msg->pid) {
        ngx_slab_free_locked(shpool, msg->pid);
    }

    if (msg->path.data) {
        ngx_slab_free_locked(shpool, msg->path.data);
    }

    if (msg->content.data) {
        ngx_slab_free_locked(shpool, msg->content.data);
    }

    ngx_slab_free_locked(shpool, msg);
}


ngx_int_t
ngx_dyups_sync_cmd(ngx_pool_t *pool, ngx_str_t *path, ngx_str_t *content,
    ngx_uint_t flag)
{
    ngx_int_t     rc;
    ngx_buf_t     body;
    ngx_str_t     name, *value, rv;
    ngx_array_t  *res, *arglist;

    res = ngx_dyups_parse_path(pool, path);
    if (res == NULL) {
        return NGX_ERROR;
    }

    if (res->nelts != 2) {
        return NGX_ERROR;
    }

    value = res->elts;

    name = value[1];

    if (flag == NGX_DYUPS_DELETE) {

        rc = ngx_dyups_do_delete(&name, &rv);
        if (rc != NGX_HTTP_OK) {
            return NGX_ERROR;
        }

        return NGX_OK;

    } else if (flag == NGX_DYUPS_ADD) {

        body.start = body.pos = content->data;
        body.end = body.last = content->data + content->len;

        arglist = ngx_dyups_parse_content(pool, &body);
        if (arglist == NULL) {
            return NGX_ERROR;
        }

        rc = ngx_dyups_do_update(&name, arglist, &rv);
        if (rc != NGX_HTTP_OK) {
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    return NGX_ERROR;
}
