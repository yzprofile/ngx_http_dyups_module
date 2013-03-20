## Description
This module can be used to update your upstream-list without reloadding Nginx.

### Config Example

    daemon off;
    error_log logs/error.log debug;

    events {
    }

    http {

        upstream host1 {
            server 127.0.0.1:8088;
        }
        
        upstream host2 {
            server 127.0.0.1:8089;
        }

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

Call the interface, when you get the return code is `500`, you need to reload nginx to make the Nginx work at a good state.

If you got 409, you need resend the same commands again latter.

The /list and /detail interface will return 204 when there is no upstream.

Other code means you should modify your commands and call the interface again.

Of course, You also need a 3-part to generate the new config and dump it to Nginx'conf directory.

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

## developing

TODO:

1. check every commands to make sure they are all ok before update upstream. `done`

2. support ip_hash and keepalive or other upstream module `done`

3. support `weight`,`max_fails`,`fail_timeout`,`backup` `done`

4. support health check module

