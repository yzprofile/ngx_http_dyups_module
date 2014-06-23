## Description
This module can be used to update your upstream-list without reloadding Nginx.

And this module compatible with [lua-upstream-nginx-module](https://github.com/agentzh/lua-upstream-nginx-module), You can use `lua-upstream-nginx-module` to get more detail infomation of upstream.

TODO:

It can not work with common `nginx_upstream_check_module`, if you still want to use this module, you can try [this branch of Tengine](https://github.com/yaoweibin/tengine/tree/dynamic_upstream_check) witch contains a patched upstream check module.

Or Use the `upstream_check-tengine-2.0.patch` to patch tengine2.0

### Config Example

file: conf/nginx.conf

    daemon off;
    error_log logs/error.log debug;

    events {
    }

    http {

        dyups_upstream_conf  conf/upstream.conf;

        include conf/upstream.conf;

        server {
            listen   8080;

            location / {
                proxy_pass http://$host;
            }
        }

        server {
            listen 8088;
            location / {
                echo 8088;
            }
        }

        server {
            listen 8089;
            location / {
                echo 8089;
            }
        }

        server {
            listen 8081;
            location / {
                dyups_interface;
            }
        }
    }


file: conf/upstream.conf

    upstream host1 {
        server 127.0.0.1:8088;
    }

    upstream host2 {
        server 127.0.0.1:8089;
    }


## Installation
```bash

$ git clone git://github.com/yzprofile/ngx_http_dyups_module.git
$ ./configure --add-module=./ngx_http_dyups_module

```

## Directives

Syntax: **dyups_interface**

Default: `none`

Context: `loc`

This directive set the interface location where you can add or delete the upstream list. See the section of Interface for detail.


Syntax: **dyups_read_msg_timeout** `time`

Default: `1s`

Context: `main`

This directive set the interval of workers readding the commands from share memory.


Syntax: **dyups_shm_zone_size** `size`

Default: `2MB`

Context: `main`

This directive set the size of share memory which used to store the commands.


Syntax: **dyups_upstream_conf** `path`

Default: `none`

Context: `main`

This directive set the path of file which you dumped all of upstreams' configs, it will be loaded in `init process` after process respwan to restore upstreams.


Syntax: **dyups_trylock** `on | off`

Default: `off`

Context: `main`

You will get a better prefomance but it maybe not stable, and you will get a '409' when the update request conflicts with others.


## restful interface

### GET
- `/detail`         get all upstreams and their servers
- `/list`           get the list of upstreams
- `/upstream/name`  find the upstream by it's name

### POST
- `/upstream/name`  update one upstream
- `body` commands;
- `body` server ip:port;

### DELETE
- `/upstream/name`  delete one upstream

Call the interface, when you get the return code is `HTTP_INTERNAL_SERVER_ERROR 500`, you need to reload nginx to make the Nginx work at a good state.

If you got `HTTP_CONFLICT 409`, you need resend the same commands again latter.

The /list and /detail interface will return `HTTP_NO_CONTENT 204` when there is no upstream.

Other code means you should modify your commands and call the interface again.

`ATTENEION`: You also need a `third-party` to generate the new config and dump it to Nginx'conf directory.

## Sample
```bash
» curl -H "host: dyhost" 127.0.0.1:8080
<html>
<head><title>502 Bad Gateway</title></head>
<body bgcolor="white">
<center><h1>502 Bad Gateway</h1></center>
<hr><center>nginx/1.3.13</center>
</body>
</html>

» curl -d "server 127.0.0.1:8089;server 127.0.0.1:8088;" 127.0.0.1:8081/upstream/dyhost
success

» curl -H "host: dyhost" 127.0.0.1:8080
8089

» curl -H "host: dyhost" 127.0.0.1:8080
8088

» curl 127.0.0.1:8081/detail
host1
server 127.0.0.1:8088

host2
server 127.0.0.1:8089

dyhost
server 127.0.0.1:8089
server 127.0.0.1:8088

» curl -i -X DELETE 127.0.0.1:8081/upstream/dyhost
success

» curl 127.0.0.1:8081/detail
host1
server 127.0.0.1:8088

host2
server 127.0.0.1:8089
```

## API
```c
extern ngx_flag_t ngx_http_dyups_api_enable;
ngx_int_t ngx_dyups_update_upstream(ngx_str_t *name, ngx_buf_t *buf,
    ngx_str_t *rv);
ngx_int_t ngx_dyups_delete_upstream(ngx_str_t *name, ngx_str_t *rv);
```

## Lua API Example
```lua
content_by_lua '
    local dyups = require "ngx.dyups"

    local status, rv = dyups.update("test", [[server 127.0.0.1:8088;]]);
    ngx.print(status, rv)
    if status ~= 200 then
        ngx.print(status, rv)
        return
    end
    ngx.print("update success")

    status, rv = dyups.delete("test")
    if status ~= 200 then
        ngx.print(status, rv)
        return
    end
    ngx.print("delete success")
';

```


## Change Log

### RELEASE V0.2.7

Supported: C API and Lua API


### RELEASE V0.2.6
Bugfixed: Supported sandbox before updatting


### RELEASE V0.2.5
1. Bugfixed: wrong string comparison for string "upstream", @chobits
2. Bugfixed: that response of /detail uri has no Content-Length header, @chobits
3. Feature: if you use this [branch of tengine](https://github.com/alibaba/tengine/tree/jst), update upstream rbtree, @SarahWang
4. Feature: simplify upstream parsing methods via ngx_conf_parse api, @chobits

### RELEASE V0.2.4

1. Bugfixed: client timed out cause a coredumped while adding an exist upstream
2. Bugfixed: when proxy_pass to a no-variable address dyups will coredump

### RELEASE V0.2.2

1. Bugfixed: upstream will be deleted in the process of finding upstream.

### RELEASE V0.2.0

1. check every commands to make sure they are all ok before update upstream. `done`

2. support ip_hash and keepalive or other upstream module `done`

3. support `weight`,`max_fails`,`fail_timeout`,`backup` `done`

4. support health check module, you should use [this branch of Tengine](https://github.com/yaoweibin/tengine/tree/dynamic_upstream_check) or wait for it's release. `done`

5. restore upstream configuration in `init process` handler. `done`


## Run Tests

```bash
$ cd /path/to/nginx-tests

$ ln /path/to/dynamic_upstream_dir/t/dyups.t ./

$ TEST_NGINX_BINARY=/path/to/your/nginx/dir/sbin/nginx prove ./dyups.t
```

## Copyright & License

These codes are licenced under the BSD license.

Copyright (C) 2012-2014 by Zhuo Yuan (yzprofile) <yzprofiles@gmail.com>, Alibaba Inc.

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

    * Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
