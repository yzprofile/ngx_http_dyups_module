# developing

TODO:

1. 输入指令合法性验证

2. 权重,重试失败次数等属性更新支持

3. 健康检查模块支持

## Config Example

    daemon off;
    error_log logs/error.log debug;

    events {
    }

    http
    {

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

## STATUS [method] GET
- /detail  返回所有upstream和server
- /list  返回所有upstream列表
- /upstream/name  返回当前upstream的server信息

## ADD [method] POST
- /upstream/name
- [body] server ip:port

## DELETE [method] DELETE
- /upstream/name

# Example
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