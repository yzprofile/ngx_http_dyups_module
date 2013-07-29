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
    ngx_uint_t                     idx;
    ngx_uint_t                    *count;
    ngx_uint_t                     deleted;
    ngx_flag_t                     dynamic;
    ngx_pool_t                    *pool;
    ngx_http_conf_ctx_t           *ctx;
    ngx_http_upstream_srv_conf_t  *upstream;
} ngx_http_dyups_srv_conf_t;


typedef struct {
    ngx_flag_t                     enable;
    ngx_flag_t                     trylock;
    ngx_array_t                    dy_upstreams;/* ngx_http_dyups_srv_conf_t */
    ngx_str_t                      conf_path;
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


typedef struct ngx_dyups_status_s {
    ngx_pid_t                            pid;
    ngx_msec_t                           time;
} ngx_dyups_status_t;


typedef struct ngx_dyups_shctx_s {
    ngx_queue_t                          msg_queue;
    ngx_uint_t                           version;
    ngx_dyups_status_t                  *status;
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
static void ngx_dyups_delete_upstream(ngx_http_dyups_srv_conf_t *duscf);
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
static void ngx_http_dyups_exit_process(ngx_cycle_t *cycle);
static void ngx_http_dyups_read_msg(ngx_event_t *ev);
static void ngx_http_dyups_read_msg_locked(ngx_event_t *ev);
static ngx_int_t ngx_http_dyups_send_msg(ngx_str_t *path, ngx_buf_t *body,
    ngx_uint_t flag);
static void ngx_dyups_destroy_msg(ngx_slab_pool_t *shpool,
    ngx_dyups_msg_t *msg);
static ngx_int_t ngx_dyups_sync_cmd(ngx_pool_t *pool, ngx_str_t *path,
    ngx_str_t *content, ngx_uint_t flag);
static ngx_array_t *ngx_dyups_parse_path(ngx_pool_t *pool, ngx_str_t *path);
static ngx_int_t ngx_dyups_do_delete(ngx_str_t *name, ngx_str_t *rv);
static ngx_int_t ngx_dyups_restore_upstreams(ngx_cycle_t *cycle,
    ngx_str_t *path);
static ngx_array_t *ngx_dyups_copy_args(ngx_pool_t *pool, ngx_array_t *arglist);
static ngx_buf_t * ngx_dyups_read_upstream_conf(ngx_cycle_t *cycle,
    ngx_str_t *path);
static ngx_int_t ngx_dyups_do_restore_upstream(ngx_buf_t *ups,
    ngx_buf_t *block);
static void ngx_dyups_purge_msg(ngx_pid_t opid, ngx_pid_t npid);
static void ngx_http_dyups_clean_request(void *data);


static ngx_command_t  ngx_http_dyups_commands[] = {

    { ngx_string("dyups_interface"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_dyups_interface,
      0,
      0,
      NULL },

    { ngx_string("dyups_read_msg_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
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

    { ngx_string("dyups_upstream_conf"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_dyups_main_conf_t, conf_path),
      NULL },

    { ngx_string("dyups_trylock"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_dyups_main_conf_t, trylock),
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
    ngx_http_dyups_exit_process,   /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_uint_t argument_number[] = {
    NGX_CONF_NOARGS,
    NGX_CONF_TAKE1,
    NGX_CONF_TAKE2,
    NGX_CONF_TAKE3,
    NGX_CONF_TAKE4,
    NGX_CONF_TAKE5,
    NGX_CONF_TAKE6,
    NGX_CONF_TAKE7
};


static ngx_http_upstream_srv_conf_t ngx_http_dyups_deleted_upstream;
static ngx_uint_t ngx_http_dyups_shm_generation = 0;
static ngx_dyups_global_ctx_t ngx_dyups_global_ctx;


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

#if (NGX_DEBUG)

    if (ngx_array_init(&dmcf->dy_upstreams, cf->pool, 1,
                       sizeof(ngx_http_dyups_srv_conf_t))
        != NGX_OK)
    {
        return NULL;
    }

#else

    if (ngx_array_init(&dmcf->dy_upstreams, cf->pool, 1024,
                       sizeof(ngx_http_dyups_srv_conf_t))
        != NGX_OK)
    {
        return NULL;
    }

#endif

    dmcf->enable = NGX_CONF_UNSET;
    dmcf->shm_size = NGX_CONF_UNSET_UINT;
    dmcf->read_msg_timeout = NGX_CONF_UNSET_MSEC;
    dmcf->trylock = NGX_CONF_UNSET;

    /*
      dmcf->conf_path = nil
     */

    return dmcf;
}


static char *
ngx_http_dyups_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_dyups_main_conf_t  *dmcf = conf;

    dmcf->enable = dmcf->enable == NGX_CONF_UNSET ? 0 : 1;
    dmcf->trylock = dmcf->trylock == NGX_CONF_UNSET ? 0 : 1;

    if (!dmcf->enable) {
        return NGX_CONF_OK;
    }

    if (dmcf->read_msg_timeout == NGX_CONF_UNSET_MSEC) {
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

    sh->version = 0;
    sh->status = NULL;

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
    ngx_url_t                            u;
    ngx_uint_t                           i;
    ngx_http_dyups_srv_conf_t           *duscf;
    ngx_http_upstream_server_t          *us;
    ngx_http_dyups_main_conf_t          *dmcf;
    ngx_http_upstream_srv_conf_t       **uscfp;
    ngx_http_upstream_main_conf_t       *umcf;
    ngx_http_dyups_upstream_srv_conf_t  *dscf;

    dmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_dyups_module);
    umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);

    if (!dmcf->enable) {
        return NGX_OK;
    }

    uscfp = umcf->upstreams.elts;
    for (i = 0; i < umcf->upstreams.nelts; i++) {

        duscf = ngx_array_push(&dmcf->dy_upstreams);
        if (duscf == NULL) {
            return NGX_ERROR;
        }

        ngx_memzero(duscf, sizeof(ngx_http_dyups_srv_conf_t));

        duscf->pool = ngx_create_pool(512, cf->log);
        if (duscf->pool == NULL) {
            return NGX_ERROR;
        }

        duscf->upstream = uscfp[i];
        duscf->dynamic = (uscfp[i]->port == 0
                          && uscfp[i]->srv_conf && uscfp[i]->servers
                          && uscfp[i]->flags & NGX_HTTP_UPSTREAM_CREATE);
        duscf->deleted = 0;
        duscf->idx = i;

        duscf->count = &dscf->count;

        if (duscf->dynamic) {
            dscf = duscf->upstream->srv_conf[ngx_http_dyups_module.ctx_index];
        }
    }

    /* alloc a dumy upstream */

    ngx_memzero(&ngx_http_dyups_deleted_upstream,
                sizeof(ngx_http_upstream_srv_conf_t));
    ngx_http_dyups_deleted_upstream.srv_conf = ((ngx_http_conf_ctx_t *)
                                                (cf->ctx))->srv_conf;
    ngx_http_dyups_deleted_upstream.servers = ngx_array_create(cf->pool, 1,
                                           sizeof(ngx_http_upstream_server_t));

    us = ngx_array_push(ngx_http_dyups_deleted_upstream.servers);
    if (us == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));
    ngx_memzero(us, sizeof(ngx_http_upstream_server_t));

    u.default_port = 80;
    ngx_str_set(&u.url, "0.0.0.0");

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "[dyups] %s in init", u.err);
        }

        return NGX_ERROR;
    }

    us->addrs = u.addrs;
    us->naddrs = u.naddrs;
    us->down = 1;

    ngx_str_set(&ngx_http_dyups_deleted_upstream.host,
                "_dyups_upstream_down_host_");
    ngx_http_dyups_deleted_upstream.file_name = (u_char *) "dyups_upstream";

    return NGX_OK;
}


static ngx_int_t
ngx_http_dyups_init_process(ngx_cycle_t *cycle)
{
    ngx_int_t                    rc, i;
    ngx_pid_t                    pid;
    ngx_time_t                  *tp;
    ngx_msec_t                   now;
    ngx_event_t                 *timer;
    ngx_core_conf_t             *ccf;
    ngx_slab_pool_t             *shpool;
    ngx_dyups_shctx_t           *sh;
    ngx_dyups_status_t          *status;
    ngx_http_dyups_main_conf_t  *dmcf;

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    dmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_http_dyups_module);

    if (!dmcf || !dmcf->enable) {
        return NGX_OK;
    }

    timer = &ngx_dyups_global_ctx.msg_timer;
    ngx_memzero(timer, sizeof(ngx_event_t));

    timer->handler = ngx_http_dyups_read_msg;
    timer->log = cycle->log;
    timer->data = dmcf;

    ngx_add_timer(timer, dmcf->read_msg_timeout);

    shpool = ngx_dyups_global_ctx.shpool;
    sh = ngx_dyups_global_ctx.sh;

    ngx_shmtx_lock(&shpool->mutex);

    if (sh->status == NULL) {
        sh->status = ngx_slab_alloc_locked(shpool,
                           sizeof(ngx_dyups_status_t) * ccf->worker_processes);

        if (sh->status == NULL) {
            ngx_shmtx_unlock(&shpool->mutex);
            return NGX_ERROR;
        }

        ngx_memzero(sh->status, sizeof(ngx_msec_t) * ccf->worker_processes);

        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_OK;
    }

    ngx_shmtx_unlock(&shpool->mutex);

    if (sh->version != 0) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                      "[dyups] process start after abnormal exits");

        ngx_msleep(dmcf->read_msg_timeout * 2);

        ngx_time_update();
        tp = ngx_timeofday();
        now = (ngx_msec_t) (tp->sec * 1000 + tp->msec);

        ngx_shmtx_lock(&shpool->mutex);

        if (sh->status == NULL) {
            ngx_shmtx_unlock(&shpool->mutex);
            return NGX_OK;
        }

        status = &sh->status[0];

        for (i = 1; i < ccf->worker_processes; i++) {

            ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                          "[dyups] process %P %ui %ui",
                          sh->status[i].pid, status->time, sh->status[i].time);

            if (status->time > sh->status[i].time) {
                status = &sh->status[i];
            }
        }

        pid = status->pid;
        status->time = now;
        status->pid = ngx_pid;

        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "[dyups] new process is %P, old process is %P",
                      ngx_pid, pid);

        ngx_dyups_purge_msg(pid, ngx_pid);

        ngx_shmtx_unlock(&shpool->mutex);


        ngx_shmtx_lock(&shpool->mutex);

        rc = ngx_dyups_restore_upstreams(cycle, &dmcf->conf_path);

        ngx_shmtx_unlock(&shpool->mutex);

        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_CRIT, cycle->log, 0,
                          "[dyups] process restore upstream failed");
        }
    }

    return NGX_OK;
}


static void
ngx_dyups_purge_msg(ngx_pid_t opid, ngx_pid_t npid)
{
    ngx_int_t            i;
    ngx_queue_t         *q;
    ngx_dyups_msg_t     *msg;
    ngx_dyups_shctx_t   *sh;

    sh = ngx_dyups_global_ctx.sh;

    for (q = ngx_queue_last(&sh->msg_queue);
         q != ngx_queue_sentinel(&sh->msg_queue);
         q = ngx_queue_prev(q))
    {
        msg = ngx_queue_data(q, ngx_dyups_msg_t, queue);

        for (i = 0; i < msg->count; i++) {
            if (msg->pid[i] == opid) {

                ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                              "[dyups] restore one pid conflict"
                              " old: %P, new: %P", opid, npid);
                msg->pid[i] = npid;
            }
        }
    }
}


static void
ngx_http_dyups_exit_process(ngx_cycle_t *cycle)
{
    ngx_uint_t                   i;
    ngx_http_dyups_srv_conf_t   *duscfs, *duscf;
    ngx_http_dyups_main_conf_t  *dumcf;

    dumcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_http_dyups_module);

    duscfs = dumcf->dy_upstreams.elts;
    for (i = 0; i < dumcf->dy_upstreams.nelts; i++) {

        duscf = &duscfs[i];

        if (duscf->pool) {
            ngx_destroy_pool(duscf->pool);
            duscf->pool = NULL;
        }
    }
}


static ngx_int_t
ngx_http_dyups_interface_handler(ngx_http_request_t *r)
{
    ngx_int_t                    rc;
    ngx_array_t                 *res;
    ngx_event_t                 *timer;
    ngx_slab_pool_t             *shpool;
    ngx_http_dyups_main_conf_t  *dmcf;

    dmcf = ngx_http_get_module_main_conf(r, ngx_http_dyups_module);
    timer = &ngx_dyups_global_ctx.msg_timer;
    shpool = ngx_dyups_global_ctx.shpool;

    res = ngx_dyups_parse_path(r->pool, &r->uri);
    if (res == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r->method == NGX_HTTP_GET) {
        ngx_http_dyups_read_msg(timer);
        return ngx_http_dyups_do_get(r, res);
    }

    if (r->method == NGX_HTTP_DELETE) {

        if (!dmcf->trylock) {

            ngx_shmtx_lock(&shpool->mutex);

        } else {

            if (!ngx_shmtx_trylock(&shpool->mutex)) {
                return NGX_HTTP_CONFLICT;
            }

        }

        ngx_http_dyups_read_msg_locked(timer);
        rc = ngx_http_dyups_do_delete(r, res);

        ngx_shmtx_unlock(&shpool->mutex);

        return rc;
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

    if (buf != NULL && ngx_buf_size(buf) == 0) {
        status = NGX_HTTP_NO_CONTENT;
    } else {
        status = buf ? NGX_HTTP_OK : NGX_HTTP_NOT_FOUND;
    }

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
    ngx_int_t                   dumy;
    ngx_http_dyups_srv_conf_t  *duscf;

    duscf = ngx_dyups_find_upstream(name, &dumy);

    if (duscf == NULL || duscf->deleted) {

        ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                      "[dyups] not find upstream %V %p", name, duscf);

        ngx_str_set(rv, "not found uptream");
        return NGX_HTTP_NOT_FOUND;
    }

    ngx_dyups_delete_upstream(duscf);

    ngx_str_set(rv, "success");

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

    status = ngx_dyups_do_delete(&name, &rv);
    if (status != NGX_HTTP_OK) {
        goto finish;
    }

    rc = ngx_http_dyups_send_msg(&r->uri, NULL, NGX_DYUPS_DELETE);
    if (rc != NGX_OK) {
        ngx_str_set(&rv, "alert: delte success but not sync to other process");
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "[dyups] %V", &rv);
        status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto finish;
    }

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
    ngx_str_t                    rv;
    ngx_int_t                    status;
    ngx_buf_t                   *body;
    ngx_event_t                 *timer;
    ngx_array_t                 *arglist, *res;
    ngx_slab_pool_t             *shpool;
    ngx_http_dyups_main_conf_t  *dmcf;

    dmcf = ngx_http_get_module_main_conf(r, ngx_http_dyups_module);
    timer = &ngx_dyups_global_ctx.msg_timer;
    shpool = ngx_dyups_global_ctx.shpool;

    if (r->method != NGX_HTTP_POST) {
        status = NGX_HTTP_NOT_ALLOWED;
        goto finish;
    }

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


    if (!dmcf->trylock) {

        ngx_shmtx_lock(&shpool->mutex);

    } else {

        if (!ngx_shmtx_trylock(&shpool->mutex)) {
            status = NGX_HTTP_CONFLICT;
            ngx_str_set(&rv, "wait and try again\n");
            goto finish;
        }
    }

    ngx_http_dyups_read_msg_locked(timer);

    status = ngx_http_dyups_do_post(r, res, arglist, &rv);

    if (status == NGX_HTTP_OK) {

        if (ngx_http_dyups_send_msg(&r->uri, body, NGX_DYUPS_ADD)) {
            ngx_str_set(&rv, "alert: update success "
                        "but not sync to other process");
            status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    ngx_shmtx_unlock(&shpool->mutex);

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
    if (duscf) {
        ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                      "[dyups] upstream reuse, idx: [%i]", idx);

        if (!duscf->deleted) {
            ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                          "[dyups] upstream delete first");
            ngx_dyups_delete_upstream(duscf);

            duscf = ngx_dyups_find_upstream(name, &idx);

            ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                          "[dyups] find another, idx: [%i]", idx);
        }
    }

    if (idx == -1) {
        /* need create a new upstream */

        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                      "[dyups] create upstream %V", name);

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

    duscf->idx = idx;
    rc = ngx_dyups_init_upstream(duscf, name, idx);

    if (rc != NGX_OK) {
        ngx_str_set(rv, "failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    arglist = ngx_dyups_copy_args(duscf->pool, arglist);
    if (arglist == NULL) {
        ngx_str_set(rv, "out of memory");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* init upstream */
    rc = ngx_dyups_add_server(duscf, arglist);
    if (rc != NGX_OK) {
        ngx_str_set(rv, "failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_str_set(rv, "success");

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

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                   "[dyups] post upstream name: %V", &name);

    rc = ngx_http_dyups_check_commands(arglist);
    if (rc != NGX_OK) {
        ngx_str_set(rv, "commands error");
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_dyups_do_update(&name, arglist, rv);
    if (rc != NGX_HTTP_OK) {
        return rc;
    }

    return NGX_HTTP_OK;
}


static ngx_int_t
ngx_dyups_add_server(ngx_http_dyups_srv_conf_t *duscf, ngx_array_t *arglist)
{
    time_t                               fail_timeout;
    unsigned                             backup;
    ngx_int_t                            weight, max_fails;
    ngx_url_t                            u;
    ngx_str_t                           *value, s;
    ngx_conf_t                           cf;
    ngx_uint_t                           i, j;
    ngx_array_t                         *line;
    ngx_command_t                       *cmd;
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

        if (ngx_strncasecmp(value[0].data, (u_char *) "server", 6) == 0) {

            backup = 0;
            weight = 1;
            max_fails = 1;
            fail_timeout = 10;

            us = ngx_array_push(uscf->servers);
            if (us == NULL) {
                return NGX_ERROR;
            }

            ngx_memzero(us, sizeof(ngx_http_upstream_server_t));
            ngx_memzero(&u, sizeof(ngx_url_t));

            u.url = value[1];
            u.default_port = 80;

            /* TODO: parse ip*/
            if (ngx_parse_url(duscf->pool, &u) != NGX_OK) {
                if (u.err) {
                    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                                  "[dyups] %s in upstream \"%V\"",
                                  u.err, &u.url);
                }

                return NGX_ERROR;
            }


            for (j = 2; j < line[i].nelts; j++) {

                if (ngx_strncmp(value[j].data, "weight=", 7) == 0) {

                    weight = ngx_atoi(&value[j].data[7], value[j].len - 7);

                    if (weight == NGX_ERROR || weight == 0) {
                        weight = 1;
                    }

                    continue;
                }

                if (ngx_strncmp(value[j].data, "max_fails=", 10) == 0) {

                    max_fails = ngx_atoi(&value[j].data[10], value[j].len - 10);
                    if (max_fails == NGX_ERROR) {
                        max_fails = 1;
                    }

                    continue;
                }

                if (ngx_strncmp(value[j].data, "fail_timeout=", 13) == 0) {

                    s.len = value[j].len - 13;
                    s.data = &value[j].data[13];

                    fail_timeout = ngx_parse_time(&s, 1);

                    if (fail_timeout == (time_t) NGX_ERROR) {
                        fail_timeout = 10;
                    }

                    continue;
                }

                if (ngx_strncmp(value[j].data, "backup", 6) == 0) {
                    backup = 1;
                    continue;
                }
            }

            us->addrs = u.addrs;
            us->naddrs = u.naddrs;
            us->weight = weight;
            us->max_fails = max_fails;
            us->fail_timeout = fail_timeout;
            us->backup = backup;

            us->addrs->name.data = ngx_pstrdup(duscf->pool, &u.addrs->name);
            us->addrs->name.len = u.addrs->name.len;

        } else {

            ngx_memzero(&cf, sizeof(ngx_conf_t));
            cf.name = "dyups_init_module_conf";
            cf.pool = duscf->pool;
            cf.module_type = NGX_HTTP_MODULE;
            cf.cmd_type = NGX_HTTP_UPS_CONF;
            cf.log = ngx_cycle->log;
            cf.ctx = duscf->ctx;
            cf.args = &line[i];

            for (j = 0; j < ngx_max_module; j++) {
                if (ngx_modules[j]->type != NGX_HTTP_MODULE) {
                    continue;
                }

                if (ngx_modules[j]->ctx_index
                    == ngx_http_upstream_module.ctx_index)
                {
                    continue;
                }

                cmd = ngx_modules[j]->commands;
                if (cmd == NULL) {
                    continue;
                }

                for ( /* void */ ; cmd->name.len; cmd++) {
                    if (!(cmd->type & NGX_HTTP_UPS_CONF)) {
                        continue;
                    }

                    if (cmd->set == NULL) {
                        continue;
                    }

                    if (cmd->name.len != value[0].len
                        || ngx_strncasecmp(cmd->name.data, value[0].data,
                                           value[0].len)
                        != 0)
                    {
                        continue;
                    }

                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                                   "[dyups] set upstream \"%V\"",
                                   &cmd->name);

                    if (cmd->set(&cf, cmd,
                            duscf->ctx->srv_conf[ngx_modules[j]->ctx_index])
                        != NGX_CONF_OK)
                    {
                        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                                      "[dyups] set upstream \"%V\" error!",
                                      &cmd->name);
                        return NGX_ERROR;
                    }
                }
            }
        }
    }

    ngx_memzero(&cf, sizeof(ngx_conf_t));
    cf.name = "dyups_init_upstream";
    cf.pool = duscf->pool;
    cf.module_type = NGX_HTTP_MODULE;
    cf.cmd_type = NGX_HTTP_MAIN_CONF;
    cf.log = ngx_cycle->log;
    cf.ctx = duscf->ctx;

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

    dumcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                                ngx_http_dyups_module);
    *idx = -1;
    duscf_del = NULL;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "[dyups] find dynamic upstream");

    duscfs = dumcf->dy_upstreams.elts;
    for (i = 0; i < dumcf->dy_upstreams.nelts; i++) {

        duscf = &duscfs[i];
        if (!duscf->dynamic) {
            continue;
        }

        if (duscf->deleted == NGX_DYUPS_DELETING) {

            ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                          "[dyups] find upstream idx: %ui %ui"
                          " requests in %V deleting",
                          i, *(duscf->count), &duscf->upstream->host);

            if (*(duscf->count) == 0) {
                ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                              "[dyups] free dynamic upstream in find upstream"
                              " %ui", duscf->idx);

                duscf->deleted = NGX_DYUPS_DELETED;
                ngx_destroy_pool(duscf->pool);
                duscf->pool = NULL;
            }
        }

        if (duscf->deleted == NGX_DYUPS_DELETING) {
            continue;
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

    duscf->pool = ngx_create_pool(512, ngx_cycle->log);
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
    if (uscf->host.data == NULL) {
        return NGX_ERROR;
    }

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
    duscf->ctx = ctx;
    duscf->deleted = 0;

    return NGX_OK;
}


static void
ngx_dyups_delete_upstream(ngx_http_dyups_srv_conf_t *duscf)
{
    ngx_uint_t                      i;
    ngx_http_upstream_server_t     *us;
    ngx_http_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_http_upstream_main_conf_t  *umcf;

    uscf = duscf->upstream;
    umcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                               ngx_http_upstream_module);
    uscfp = umcf->upstreams.elts;

    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                  "[dyups] delete upstream \"%V\"", &duscf->upstream->host);

    us = uscf->servers->elts;
    for (i = 0; i < uscf->servers->nelts; i++) {
        us[i].down = 1;

#if (NGX_HTTP_UPSTREAM_CHECK)
        ngx_http_upstream_check_delete_dynamic_peer(&uscf->host, us[i].addrs);
#endif
    }

    uscfp[duscf->idx] = &ngx_http_dyups_deleted_upstream;

    duscf->deleted = NGX_DYUPS_DELETING;
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
    ngx_int_t       rc;
    ngx_url_t       u;
    ngx_str_t      *value;
    ngx_flag_t      found, match;
    ngx_pool_t     *pool;
    ngx_uint_t      i, j;
    ngx_array_t    *line;
    ngx_command_t  *cmd;

    pool = ngx_create_pool(512, ngx_cycle->log);
    if (pool == NULL) {
        return NGX_ERROR;
    }

    found = 1;
    line = arglist->elts;
    for (i = 0; i < arglist->nelts; i++) {
        value = line[i].elts;

        /* TODO */
        if (value[0].len == 6 &&
            ngx_strncasecmp(value[0].data, (u_char *) "server", 6) == 0)
        {
            ngx_memzero(&u, sizeof(ngx_url_t));
            found = 1;

            u.url = value[1];
            u.default_port = 80;

            if (line[i].nelts < 2) {
                rc = NGX_ERROR;
                goto finish;
            }

            if (ngx_parse_url(pool, &u) != NGX_OK) {

                if (u.err) {
                    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                                  "[dyups] %s in upstream \"%V\"",
                                  u.err, &u.url);
                }

                rc = NGX_ERROR;
                goto finish;
            }

        } else {

            match = 0;
            for (j = 0; j < ngx_max_module; j++) {
                if (ngx_modules[j]->type != NGX_HTTP_MODULE) {
                    continue;
                }

                if (ngx_modules[j]->ctx_index
                    == ngx_http_upstream_module.ctx_index)
                {
                    continue;
                }

                cmd = ngx_modules[j]->commands;
                if (cmd == NULL) {
                    continue;
                }

                for ( /* void */ ; cmd->name.len; cmd++) {

                    if (!(cmd->type & NGX_HTTP_UPS_CONF)) {
                        continue;
                    }

                    if (cmd->set == NULL) {
                        continue;
                    }

                    if (cmd->name.len != value[0].len
                        || ngx_strncasecmp(cmd->name.data, value[0].data,
                                           value[0].len) != 0)
                    {
                        continue;
                    }

                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                                   "[dyups] check upstream \"%V\"",
                                   &cmd->name);
                    match = 1;

                    if (!(cmd->type & NGX_CONF_ANY)) {

                        if (cmd->type & NGX_CONF_FLAG) {

                            if (line[i].nelts != 2) {
                                rc = NGX_ERROR;
                                goto finish;
                            }

                        } else if (cmd->type & NGX_CONF_1MORE) {

                            if (line[i].nelts < 2) {
                                rc = NGX_ERROR;
                                goto finish;
                            }

                        } else if (cmd->type & NGX_CONF_2MORE) {

                            if (line[i].nelts < 3) {
                                rc = NGX_ERROR;
                                goto finish;
                            }

                        } else if (line[i].nelts > NGX_CONF_MAX_ARGS) {

                            rc = NGX_ERROR;
                            goto finish;

                        } else if (!(cmd->type
                                     & argument_number[line[i].nelts - 1]))
                        {
                            rc = NGX_ERROR;
                            goto finish;
                        }

                    }

                }

            }

            if (!match) {
                rc = NGX_ERROR;
                goto finish;
            }

        }
    }

    if (!found) {
        rc = NGX_ERROR;
        goto finish;
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
    ngx_array_t  *args_list, *args;

#if (NGX_DEBUG)

    args_list = ngx_array_create(pool, 1, sizeof(ngx_array_t));

#else

    args_list = ngx_array_create(pool, 16, sizeof(ngx_array_t));

#endif

    if (args_list == NULL) {
        return NULL;
    }

    body = *buf;

    for ( ;; ) {

        args = ngx_array_push(args_list);
        if (args == NULL) {
            return NULL;
        }

#if (NGX_DEBUG)
        rc = ngx_array_init(args, pool, 1, sizeof(ngx_str_t));

#else
        rc = ngx_array_init(args, pool, 16, sizeof(ngx_str_t));

#endif
        if (rc != NGX_OK) {
            return NULL;
        }

        rc = ngx_dyups_conf_read_token(pool, &body, args);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pool->log, 0,
                       "[dyups] read token rc: %i", rc);

        if (rc == NGX_OK) {

#if (NGX_DEBUG)
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

#if (NGX_DEBUG)
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
    ngx_pool_cleanup_t                  *cln;
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

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_http_dyups_clean_request;
    cln->data = ctx;

    return NGX_OK;
}


static void
ngx_http_dyups_clean_request(void *data)
{
    ngx_http_dyups_ctx_t  *ctx = data;

    ctx->scf->count--;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "[dyups] http clean request count %i",
                   ctx->scf->count);
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

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "[dyups] dynamic upstream free handler count %i",
                   ctx->scf->count);

    ctx->free(pc, ctx->data, state);
}


static void
ngx_http_dyups_read_msg(ngx_event_t *ev)
{
    ngx_uint_t                   i, count, s_count, d_count;
    ngx_slab_pool_t             *shpool;
    ngx_http_dyups_srv_conf_t   *duscfs, *duscf;
    ngx_http_dyups_main_conf_t  *dmcf;

    dmcf = ev->data;
    shpool = ngx_dyups_global_ctx.shpool;

    count = 0;
    s_count = 0;
    d_count = 0;

    duscfs = dmcf->dy_upstreams.elts;
    for (i = 0; i < dmcf->dy_upstreams.nelts; i++) {

        duscf = &duscfs[i];

        if (!duscf->dynamic) {
            s_count++;
            continue;
        }

        if (duscf->deleted) {
            d_count++;
            continue;
        }

        count++;
    }

    ngx_log_error(NGX_LOG_INFO, ev->log, 0,
                  "[dyups] has %ui upstreams, %ui static, %ui deleted, all %ui",
                  count, s_count, d_count, dmcf->dy_upstreams.nelts);

    ngx_shmtx_lock(&shpool->mutex);

    ngx_http_dyups_read_msg_locked(ev);

    ngx_shmtx_unlock(&shpool->mutex);

    ngx_dyups_add_timer(ev, dmcf->read_msg_timeout);
}


static void
ngx_http_dyups_read_msg_locked(ngx_event_t *ev)
{
    ngx_int_t            i, rc;
    ngx_str_t            path, content;
    ngx_flag_t           found;
    ngx_time_t          *tp;
    ngx_pool_t          *pool;
    ngx_msec_t           now;
    ngx_queue_t         *q, *t;
    ngx_core_conf_t     *ccf;
    ngx_slab_pool_t     *shpool;
    ngx_dyups_msg_t     *msg;
    ngx_dyups_shctx_t   *sh;
    ngx_dyups_status_t  *status;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "[dyups] read msg %P", ngx_pid);

    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                           ngx_core_module);

    sh = ngx_dyups_global_ctx.sh;
    shpool = ngx_dyups_global_ctx.shpool;

    tp = ngx_timeofday();
    now = (ngx_msec_t) (tp->sec * 1000 + tp->msec);

    for (i = 0; i < ccf->worker_processes; i++) {
        status = &sh->status[i];

        if (status->pid == 0 || status->pid == ngx_pid) {

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                           "[dyups] process %P update time %ui",
                           status->pid, status->time);

            status->pid = ngx_pid;
            status->time = now;
            break;
        }
    }

    if (ngx_queue_empty(&sh->msg_queue)) {
        return;
    }

    pool = ngx_create_pool(ngx_pagesize, ev->log);
    if (pool == NULL) {
        return;
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

        found = 0;
        for (i = 0; i < msg->count; i++) {

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                           "[dyups] msg pids [%P]", msg->pid[i]);

            if (msg->pid[i] == ngx_pid) {
                found = 1;
                break;
            }
        }

        if (found) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                           "[dyups] msg %V count %ui found",
                           &msg->path, msg->count);
            continue;
        }

        msg->pid[i] = ngx_pid;
        msg->count++;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                       "[dyups] msg %V count %ui", &msg->path, msg->count);

        path = msg->path;
        content = msg->content;

        rc = ngx_dyups_sync_cmd(pool, &path, &content, msg->flag);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                          "[dyups] read msg error, may cause the "
                          "config inaccuracy, path:%V, content:%V",
                          &path, &content);
        }
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "[dyups] read end");

    ngx_destroy_pool(pool);

    return;
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

    msg = ngx_slab_alloc_locked(shpool, sizeof(ngx_dyups_msg_t));
    if (msg == NULL) {
        goto failed;
    }

    ngx_memzero(msg, sizeof(ngx_dyups_msg_t));

    msg->flag = flag;
    msg->count = 0;
    msg->pid = ngx_slab_alloc_locked(shpool,
                                     sizeof(ngx_pid_t) * ccf->worker_processes);

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

    sh->version++;

    if (sh->version == 0) {
        sh->version = 1;
    };

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "[dyups] send msg %V count %ui version: %ui",
                   &msg->path, msg->count, sh->version);

    ngx_queue_insert_head(&sh->msg_queue, &msg->queue);

    return NGX_OK;

failed:

    if (msg) {
        ngx_dyups_destroy_msg(shpool, msg);
    }

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


static ngx_int_t
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

        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                       "[dyups] sync del: %V rv: %V rc: %i",
                       &name, &rv, rc);

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

        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                      "[dyups] sync add: %V rv: %V rc: %i",
                      &name, &rv, rc);

        if (rc != NGX_HTTP_OK) {
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    return NGX_ERROR;
}


static ngx_array_t *
ngx_dyups_copy_args(ngx_pool_t *pool, ngx_array_t *arglist)
{
    ngx_int_t     rc;
    ngx_str_t    *s, *st;
    ngx_uint_t    i, j;
    ngx_array_t  *al, *as, *ast;

    al = ngx_array_create(pool, arglist->nelts, sizeof(ngx_array_t));
    if (al == NULL) {
        return NULL;
    }

    ast = arglist->elts;

    for (i = 0; i < arglist->nelts; i++) {

        as = ngx_array_push(al);

        if (as == NULL) {
            return NULL;
        }

        rc = ngx_array_init(as, pool, ast[i].nelts, sizeof(ngx_str_t));
        if (rc != NGX_OK) {
            return NULL;
        }

        st = ast[i].elts;

        for (j = 0; j < ast[i].nelts; j++) {

            s = ngx_array_push(as);

            if (s == NULL) {
                return NULL;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pool->log, 0,
                           "[dyups] copy arg: %V", &st[j]);

            s->data = ngx_pcalloc(pool, st[j].len + 1);

            ngx_memcpy(s->data, st[j].data, st[j].len);
            s->len = st[j].len;
        }
    }

    return al;
}


static ngx_buf_t *
ngx_dyups_read_upstream_conf(ngx_cycle_t *cycle, ngx_str_t *path)
{
    off_t             file_size;
    ssize_t           n, size;
    ngx_str_t         full;
    ngx_buf_t        *buf;
    ngx_file_t        file;
    ngx_file_info_t   fi;

    full = *path;

    if (ngx_conf_full_name(cycle, &full, 0) != NGX_OK) {
        return NULL;
    }

    ngx_memzero(&file, sizeof(ngx_file_t));

    file.name = *path;
    file.log = cycle->log;

    file.fd = ngx_open_file(full.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_CRIT, cycle->log, ngx_errno,
                      ngx_open_file_n " \"%V\" failed", &full);
        return NULL;
    }

    if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      ngx_fd_info_n " \"%V\" failed", path);
        return NULL;
    }

    file_size = ngx_file_size(&fi);

    buf = ngx_create_temp_buf(cycle->pool, file_size + 1);

    if (buf == NULL) {
        return NULL;
    }

    for ( ;; ) {

        size = (ssize_t) (file_size - file.offset);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cycle->log, 0,
                       "[dyups] read size: %i", size);

        if (size <= 0) {
            break;
        }

        n = ngx_read_file(&file, buf->last, size, file.offset);

        if (n == NGX_ERROR) {
            return NULL;
        }

        if (n != size) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          ngx_read_file_n " returned "
                          "only %z bytes instead of %z",
                          n, size);
            return NULL;
        }

        buf->last += size;
    }

    return buf;
}


static ngx_int_t
ngx_dyups_restore_upstreams(ngx_cycle_t *cycle, ngx_str_t *path)
{
    u_char     *p;
    ngx_int_t   rc;
    ngx_buf_t  *buf, ups, block;
    ngx_uint_t  c, in, c1, c2, sharp_comment;

    if (path->len == 0) {
        return NGX_OK;
    }

    buf = ngx_dyups_read_upstream_conf(cycle, path);

    if (buf == NULL) {
        return NGX_ERROR;
    }

#if 1
    for (p = buf->pos; p < buf->last; p++) {
       fprintf(stderr, "%c", *p);
    }
#endif

    in = 0;
    c = 0;

    c1 = c2 = 0;
    sharp_comment = 0;

    for (p = buf->pos; p < buf->last; p++) {

        if (*p == '#') {
            sharp_comment = 1;
            continue;
        }

        if (*p == LF) {
            if (sharp_comment == 1) {
                sharp_comment = 0;
            }
        }

        if (sharp_comment) {
            continue;
        }

        switch (*p) {

        case '{':

            c++;
            in = 1;
            *p = ';';

            ups.last = ups.end = p + 1;
            block.pos = block.start = p + 1;

            break;

        case '}':

            if (c == 0 || in == 0) {
                return NGX_ERROR;
            }

            c--;

            if (c == 0 && in) {
                in = 0;

                block.last = block.end = p;

                c1++;

                ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0,
                              "[dyups] c1 = %ui, c2 = %ui", c1, c2);

                if (c1 != c2) {
                    return NGX_ERROR;
                }

                rc = ngx_dyups_do_restore_upstream(&ups, &block);
                if (rc != NGX_OK) {
                    return NGX_ERROR;
                }

            }

            break;

        default:

            if (in) {


            } else {

                if (ngx_strncmp(p, "upstream", 8) == 0) {

                    ups.pos = ups.start = p;

                    p += 8;
                    c2++;
                }

            }

        }
    }

    ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0,
                  "[dyups] c1 = %ui, c2 = %ui", c1, c2);

    return NGX_OK;
}


static ngx_int_t
ngx_dyups_do_restore_upstream(ngx_buf_t *ups, ngx_buf_t *block)
{

#if 0
    u_char  *p;

    for (p = ups->pos; p < ups->last; p++) {
       fprintf(stderr, "%c", *p);
    }

    fprintf(stderr, "\n");

    for (p = block->pos; p < block->last; p++) {
       fprintf(stderr, "%c", *p);
    }

    fprintf(stderr, "\n");

#endif

    ngx_int_t     rc;
    ngx_str_t    *v, name, rv;
    ngx_pool_t   *pool;
    ngx_array_t  *aups, *ablock;

    pool = ngx_create_pool(ngx_pagesize, ngx_cycle->log);
    if (pool == NULL) {
        return NGX_ERROR;
    }

    aups = ngx_dyups_parse_content(pool, ups);
    if (aups == NULL) {
        goto failed;
    }

    if (aups->nelts != 1) {
        goto failed;
    }

    aups = aups->elts;

    if (aups->nelts != 2) {
        goto failed;
    }

    v = aups->elts;

    if (ngx_strncmp(v[0].data, "upstream", 8) != 0) {
        goto failed;
    }

    name = v[1];

    ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                  "[dyups] restore %V", &name);

    ablock = ngx_dyups_parse_content(pool, block);
    if (ablock == NULL) {
        goto failed;
    }

    rc = ngx_dyups_do_update(&name, ablock, &rv);

    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                  "[dyups] restore add: %V rv: %V rc: rc: %i",
                  &name, &rv, rc);
    if (rc != NGX_HTTP_OK) {
        goto failed;
    }

    ngx_destroy_pool(pool);

    return NGX_OK;

failed:
    if (pool) {
        ngx_destroy_pool(pool);
    }

    return NGX_ERROR;
}
