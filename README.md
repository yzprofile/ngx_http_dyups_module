# developing

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

            location /1 {
                proxy_pass http://$host;
            }

            location /2 {
                proxy_pass http://$host;
            }
            location /3 {
                proxy_pass http://127.0.0.1:8089;    
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
`(developing)`
- /detail  返回所有upstream和server
- /list  返回所有upstream列表
- /upstream/name  返回当前upstream的server信息

## ADD [method] POST
- /upstream/name
- [body] server ip:port

## DELETE [method] DELETE
- /upstream/name

# Example

	» curl -H "host: dyhost" 127.0.0.1:8080/1
	<html>
	<head><title>502 Bad Gateway</title></head>
	<body bgcolor="white">
	<center><h1>502 Bad Gateway</h1></center>
	<hr><center>nginx/1.3.13</center>
	</body>
	</html>

	» curl -d "server 127.0.0.1:8089;server 127.0.0.1:8088;" 127.0.0.1:8081/upstream/dyhost
	success

	» curl -H "host: dyhost" 127.0.0.1:8080/1
	8089

	» curl -H "host: dyhost" 127.0.0.1:8080/1
	8088
