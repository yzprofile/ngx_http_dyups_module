#
# test of `ngx_http_upstream_check_module`
# @see https://github.com/yzprofile/nginx_upstream_check_module
# @see https://github.com/alibaba/tengine/tree/master/modules/ngx_http_upstream_check_module
#
use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use File::Path;
use Test::Nginx;

use lib $FindBin::Bin;
use mhttp;

my $t = Test::Nginx->new()->plan(14);

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

warn "your test dir is ".$t->testdir();

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

worker_processes auto;

events {
    accept_mutex off;
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
            return 200 "8088";
        }
    }

    server {
        listen unix:/tmp/dyupssocket;
        location / {
            return 200 "unix";
        }
    }

    server {
        listen 8089;
        location / {
            return 200 "8089";
        }
    }

    server {
        listen 8081;
        location / {
            dyups_interface;
        }
    }
}
EOF

mrun($t);

###############################################################################
my $rep;
my $body;

$rep = qr/
host1
host2
/m;
like(mhttp_get('/list', 'localhost', 8081), $rep, '2013-02-26 16:51:46');
$rep = qr/
host1
server 127.0.0.1:8088 weight=1 .*

host2
server 127.0.0.1:8089 weight=1 .*
/m;
like(mhttp_get('/detail', 'localhost', 8081), $rep, '2013-02-26 17:30:07');
like(mhttp_get('/upstream/host1', 'localhost', 8081), qr/server 127.0.0.1:8088/m, '2013-02-26 17:35:19');

###############################################################################

like(mhttp_post('/upstream/dyhost', 'server 127.0.0.1:8088;check interval=3000 rise=2 fall=5 timeout=1000 type=http default_down=false;', 8081),
     qr/success/m, '2013-03-25 10:29:48');
sleep(1);
like(mhttp_get('/', 'dyhost', 8080), qr/8088/m, '2013-03-25 10:39:03');
like(mhttp_delete('/upstream/dyhost', 8081), qr/success/m, '2013-03-25 10:39:28');
sleep(1);
like(mhttp_get('/', 'dyhost', 8080), qr/502/m, '2013-03-25 10:39:03');

like(mhttp_post('/upstream/dyhost', 'server 127.0.0.1:8089;check interval=3000 rise=2 fall=5 timeout=1000 type=http default_down=true;', 8081),
     qr/success/m, '2013-03-25 10:49:44');
sleep(1);
like(mhttp_get('/', 'dyhost', 8080), qr/502/m, '2013-03-25 10:50:41');
sleep(3);
like(mhttp_get('/', 'dyhost', 8080), qr/8089/m, '2013-03-25 10:50:50');
like(mhttp_delete('/upstream/dyhost', 8081), qr/success/m, '2013-03-25 10:49:51');
sleep(1);
like(mhttp_get('/', 'dyhost', 8080), qr/502/m, '2013-03-25 10:39:03');

like(mhttp_post('/upstream/dyhost', 'server 127.0.0.1:8088;', 8081), qr/success/m, '2014-06-15 07:45:30');
sleep(1);
like(mhttp_get('/', 'dyhost', 8080), qr/8088/m, '2014-06-15 07:45:33');

$t->stop();
unlink("/tmp/dyupssocket");
