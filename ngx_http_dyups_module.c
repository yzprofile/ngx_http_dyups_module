#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_DYUPS_UPSTREAM_ADD     0x0001
#define NGX_HTTP_DYUPS_UPSTREAM_DELETE  0x0002


typedef struct {
    ngx_flag_t                     dynamic;
    ngx_pool_t                    *pool;
    ngx_http_upstream_srv_conf_t  *upstream;
} ngx_http_dyups_srv_conf_t;


typedef struct {
    ngx_flag_t       enable;
    ngx_array_t      dy_upstreams;   /* ngx_http_dyups_srv_conf_t */
} ngx_http_dyups_main_conf_t;


static ngx_int_t ngx_http_dyups_init(ngx_conf_t *cf);
static void *ngx_http_dyups_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_dyups_init_main_conf(ngx_conf_t *cf, void *conf);
static char *ngx_http_dyups_interface(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_dyups_interface_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dyups_interface_do_get(ngx_http_request_t *r);
static ngx_int_t ngx_http_dyups_interface_read_body(ngx_http_request_t *r);
static ngx_buf_t *ngx_http_dyups_read_body(ngx_http_request_t *r);
static ngx_buf_t *ngx_http_dyups_read_body_from_file(ngx_http_request_t *r);
static void ngx_http_dyups_body_handler(ngx_http_request_t *r);
static ngx_array_t *ngx_dyups_parse_content(ngx_pool_t *pool, ngx_buf_t *buf);
static ngx_int_t ngx_dyups_conf_read_token(ngx_pool_t *pool, ngx_buf_t *body,
    ngx_array_t *args);
static ngx_array_t *ngx_http_dyups_parse_path(ngx_http_request_t *r);
static void ngx_http_dyups_send_response(ngx_http_request_t *r,
    ngx_int_t status, ngx_str_t *content);
static ngx_int_t ngx_http_dyups_do_post(ngx_http_request_t *r,
    ngx_array_t *resource, ngx_array_t *arglist, ngx_str_t *rv);
static ngx_int_t ngx_http_dyups_do_put(ngx_http_request_t *r,
    ngx_array_t *resource, ngx_array_t *arglist, ngx_str_t *rv);
static ngx_int_t ngx_http_dyups_do_delete(ngx_http_request_t *r,
    ngx_array_t *resource, ngx_array_t *arglist, ngx_str_t *rv);
static ngx_http_dyups_srv_conf_t *ngx_dyups_update_upstream(
    ngx_str_t *name, ngx_uint_t flag, ngx_log_t *log);
static ngx_int_t ngx_dyups_add_server(ngx_http_dyups_srv_conf_t *duscf,
    ngx_array_t *arglist);
static ngx_int_t ngx_dyups_reinit_upstream(ngx_http_dyups_srv_conf_t *duscf,
    ngx_str_t *name, ngx_uint_t index);
static ngx_int_t ngx_http_dyups_check_commands(ngx_array_t *arglist);


static ngx_command_t  ngx_http_dyups_commands[] = {

    { ngx_string("dyups_interface"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_dyups_interface,
      0,
      0,
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_dyups_module_ctx = {
    NULL,                             /* preconfiguration */
    ngx_http_dyups_init,              /* postconfiguration */

    ngx_http_dyups_create_main_conf,  /* create main configuration */
    ngx_http_dyups_init_main_conf,    /* init main configuration */

    NULL,                             /* create server configuration */
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
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


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

    return dmcf;
}


static char *
ngx_http_dyups_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_dyups_main_conf_t  *dmcf = conf;

    dmcf->enable = dmcf->enable == NGX_CONF_UNSET ? 0 : 1;

    return NGX_CONF_OK;
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
        duscf->dynamic = (uscfp[i]->no_port == 1
                          && uscfp[i]->port == 0
                          && uscfp[i]->flags & NGX_HTTP_UPSTREAM_CREATE);

    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_dyups_interface_handler(ngx_http_request_t *r)
{
    if (r->method == NGX_HTTP_GET) {
        return ngx_http_dyups_interface_do_get(r);
    }

    return ngx_http_dyups_interface_read_body(r);
}


static ngx_int_t
ngx_http_dyups_interface_do_get(ngx_http_request_t *r)
{
    ngx_int_t  rc;

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }
    
    return NGX_HTTP_OK;
}


static ngx_int_t
ngx_http_dyups_interface_read_body(ngx_http_request_t *r)
{
    ngx_int_t               rc;

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

    res = ngx_http_dyups_parse_path(r);
    if (res == NULL) {
        ngx_str_set(&rv, "out of memory");
        status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto failed;
    }

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        status = NGX_HTTP_NO_CONTENT;
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "interface no content");
        ngx_str_set(&rv, "no content\n");
        goto failed;
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
        goto failed;
    }

    arglist = ngx_dyups_parse_content(r->pool, body);
    if (arglist == NULL) {
        status = NGX_HTTP_BAD_REQUEST;
        ngx_str_set(&rv, "parse body error\n");
        goto failed;
    }

    switch(r->method) {
    case NGX_HTTP_POST:
        status = ngx_http_dyups_do_post(r, res, arglist, &rv);
        break;
    case NGX_HTTP_PUT:
        status = ngx_http_dyups_do_put(r, res, arglist, &rv);
        break;
    case NGX_HTTP_DELETE:
        status = ngx_http_dyups_do_delete(r, res, arglist, &rv);
        break;
    default:
        status = NGX_HTTP_NOT_ALLOWED;
        break;
    }

failed:

    ngx_http_dyups_send_response(r, status, &rv);
}


/*
  url: /upstream
  body: server ip:port weight
 */
static ngx_int_t
ngx_http_dyups_do_post(ngx_http_request_t *r, ngx_array_t *resource,
    ngx_array_t *arglist, ngx_str_t *rv)
{
    ngx_int_t                   rc;
    ngx_str_t                  *value, name;
    ngx_http_dyups_srv_conf_t  *duscf;

    if (resource->nelts != 2) {
        ngx_str_set(rv, "not support this interface");
        return NGX_HTTP_NOT_FOUND;
    }

    value = resource->elts;

    if (ngx_strncmp(value[0].data, "upstream", 8) != 0) {
        ngx_str_set(rv, "not support this api");
        return NGX_HTTP_NOT_FOUND;
    }

    name = value[1];

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "upstream name: %V", &name);

    rc = ngx_http_dyups_check_commands(arglist);
    if (rc != NGX_OK) {
        ngx_str_set(rv, "commands error");
        return NGX_HTTP_NOT_ALLOWED;
    }

    duscf = ngx_dyups_update_upstream(&name,
                                     NGX_HTTP_DYUPS_UPSTREAM_ADD,
                                     r->connection->log);
    if (duscf == NULL) {
        ngx_str_set(rv, "add upstream error");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_dyups_add_server(duscf, arglist);
    if (rc != NGX_OK) {
        ngx_str_set(rv, "failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_str_set(rv, "success");

    return NGX_HTTP_OK;
}


static ngx_int_t
ngx_dyups_add_server(ngx_http_dyups_srv_conf_t *duscf, ngx_array_t *arglist)
{
    ngx_url_t                      u;
    ngx_str_t                     *value;
    ngx_conf_t                     cf;
    ngx_uint_t                     i;
    ngx_array_t                   *line;
    ngx_http_upstream_init_pt      init;
    ngx_http_upstream_server_t    *us;
    ngx_http_upstream_srv_conf_t  *uscf;

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
        if (ngx_strncmp(value[0].data, "server", 6) == 0) {

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
				       "%s in upstream \"%V\"", u.err, &u.url);
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

    return NGX_OK;
}


static ngx_int_t
ngx_http_dyups_do_put(ngx_http_request_t *r, ngx_array_t *resource,
    ngx_array_t *arglist, ngx_str_t *rv)
{
    return NGX_HTTP_OK;
}


static ngx_int_t
ngx_http_dyups_do_delete(ngx_http_request_t *r, ngx_array_t *resource,
    ngx_array_t *arglist, ngx_str_t *rv)
{
    ngx_str_t                  *value, name;
    ngx_http_dyups_srv_conf_t  *duscf;

    if (resource->nelts != 2) {
        ngx_str_set(rv, "not support this interface");
        return NGX_HTTP_NOT_FOUND;
    }

    value = resource->elts;

    if (ngx_strncmp(value[0].data, "upstream", 8) != 0) {
        ngx_str_set(rv, "not support this api");
        return NGX_HTTP_NOT_FOUND;
    }

    name = value[1];

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "delete upstream name: %V", &name);

    duscf = ngx_dyups_update_upstream(&name,
                                     NGX_HTTP_DYUPS_UPSTREAM_DELETE,
                                     r->connection->log);
    if (duscf == NULL) {
        ngx_str_set(rv, "delete upstream error");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* TODO: delete from upstream array */

    ngx_str_set(rv, "success");

    return NGX_HTTP_OK;
}


static ngx_http_dyups_srv_conf_t *
ngx_dyups_update_upstream(ngx_str_t *name, ngx_uint_t flag, ngx_log_t *log)
{
    void                           *mconf;
    ngx_uint_t                      i, m;
    ngx_conf_t                      cf;
    ngx_http_module_t              *module;
    ngx_http_conf_ctx_t            *ctx;
    ngx_http_dyups_srv_conf_t      *duscfs, *duscf;
    ngx_http_dyups_main_conf_t     *dumcf;
    ngx_http_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_http_upstream_main_conf_t  *umcf;

    umcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_http_upstream_module);
    dumcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                                ngx_http_dyups_module);
    duscfs = dumcf->dy_upstreams.elts;
    for (i = 0; i < dumcf->dy_upstreams.nelts; i++) {

        duscf = &duscfs[i];
        if (!duscf->dynamic) {
            continue;
        }

        uscf = duscf->upstream;

        if (uscf->host.len != name->len
            || ngx_strncasecmp(uscf->host.data, name->data, uscf->host.len)
               != 0)
        {
            continue;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "upstream matched %V", name);

	if (ngx_dyups_reinit_upstream(duscf, name, i) != NGX_OK) {

	    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
			   "upstream %V reinit error", name);

	    return NULL;
	}

        return duscf;
    }

    /* TODO: DELETE */

    if (flag != NGX_HTTP_DYUPS_UPSTREAM_ADD) {

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "upstream not find %V", name);

        return NULL;
    }

    /* NGX_HTTP_DYUPS_UPSTREAM_ADD */

    duscf = ngx_array_push(&dumcf->dy_upstreams);
    if (duscf == NULL) {
        return NULL;
    }

    duscf->pool = ngx_create_pool(128, ngx_cycle->log);
    if (duscf->pool == NULL) {
        return NULL;
    }

    uscf = ngx_pcalloc(duscf->pool, sizeof(ngx_http_upstream_srv_conf_t));
    if (uscf == NULL) {
        return NULL;
    }

    uscfp = ngx_array_push(&umcf->upstreams);
    if (uscfp == NULL) {
        return NULL;
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
    uscf->no_port = 1;

    *uscfp = uscf;

    duscf->dynamic = 1;
    duscf->upstream = uscf;

    cf.module_type = NGX_HTTP_MODULE;
    cf.cmd_type = NGX_HTTP_MAIN_CONF;
    cf.pool = duscf->pool;

    ctx = ngx_pcalloc(duscf->pool, sizeof(ngx_http_conf_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->main_conf = ((ngx_http_conf_ctx_t *)
                      ngx_cycle->conf_ctx[ngx_http_module.index])->main_conf;

    ctx->srv_conf = ngx_pcalloc(cf.pool, sizeof(void *) * ngx_http_max_module);
    if (ctx->srv_conf == NULL) {
        return NULL;
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
                return NGX_CONF_ERROR;
            }

            ctx->srv_conf[ngx_modules[m]->ctx_index] = mconf;
        }
    }

    return duscf;
}


static ngx_int_t
ngx_dyups_reinit_upstream(ngx_http_dyups_srv_conf_t *duscf, ngx_str_t *name,
    ngx_uint_t index)
{
    void                           *mconf;
    ngx_uint_t                      m;
    ngx_conf_t                      cf;
    ngx_http_module_t              *module;
    ngx_http_conf_ctx_t            *ctx;
    ngx_http_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_http_upstream_main_conf_t  *umcf;

    umcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_http_upstream_module);
    uscfp = umcf->upstreams.elts;

    ngx_destroy_pool(duscf->pool);
    duscf->pool = ngx_create_pool(128, ngx_cycle->log);

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
    uscf->no_port = 1;

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

    rc = NGX_OK;

    line = arglist->elts;
    for (i = 0; i < arglist->nelts; i++) {
        value = line[i].elts;

        /* TODO */

	if (line[i].nelts != 2) {
	    rc = NGX_ERROR;
	    goto finish;
	}

        if (ngx_strncmp(value[0].data, "server", 6) != 0) {
	    rc = NGX_ERROR;
	    goto finish;
        }

	u.url = value[1];
	u.default_port = 80;

	if (ngx_parse_url(pool, &u) != NGX_OK) {

	    if (u.err) {
		ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, 0,
			      "%s in upstream \"%V\"", u.err, &u.url);
	    }

	    rc = NGX_ERROR;
	    goto finish;
	}

    }

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
                       "read token rc: %i", rc);

        if (rc == NGX_OK) {

#if NGX_DEBUG
            ngx_str_t  *arg;
            ngx_uint_t  i;

            arg = args->elts;
            for (i = 0; i < args->nelts; i++) {
                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pool->log, 0,
                               "arg[%i]:%V", i, &arg[i]);
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
                   "interface read post body");

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
                   "interface read post body from file");

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
                   "interface read post body file size %ui", len);

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
ngx_http_dyups_parse_path(ngx_http_request_t *r)
{
    u_char       *p, *last, *end;
    ngx_str_t    *str;
    ngx_array_t  *array;

    array = ngx_array_create(r->pool, 8, sizeof(ngx_str_t));
    if (array == NULL) {
        return NULL;
    }

    p = r->uri.data + 1;
    last = r->uri.data + r->uri.len;

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
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "res[%i]:%V", i, &arg[i]);
    }
#endif

    return array;
}
