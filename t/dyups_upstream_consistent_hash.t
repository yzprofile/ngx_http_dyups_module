#
# test of `tengine/ngx_http_upstream_consistent_hash_module`
# @see https://github.com/alibaba/tengine/tree/master/modules/ngx_http_upstream_consistent_hash_module
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

my $t = Test::Nginx->new()->plan(9);

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

like(mhttp_post('/upstream/consistent_hash', <<'EOF', 8081), qr/success/m, '2018-12-30 11:11:37');
consistent_hash $arg_ds$arg_foo$arg_bar;
server 127.0.0.1:8088;
server 127.0.0.1:8089;
EOF

sleep(1);

$rep = qr/
consistent_hash
server 127.0.0.1:8088 .*
server 127.0.0.1:8089 .*
/m;


like(mhttp_get('/detail', 'locahost', 8081), $rep, '2013-03-25 10:49:47');
like(mhttp_get('/?ds=1', 'consistent_hash', 8080), qr/8089/m, '2018-12-30 11:11:40');
like(mhttp_get('/?ds=2', 'consistent_hash', 8080), qr/8088/m, '2018-12-30 11:11:41');
like(mhttp_get('/?ds=3', 'consistent_hash', 8080), qr/8088/m, '2018-12-30 11:11:42');
like(mhttp_get('/?ds=4', 'consistent_hash', 8080), qr/8088/m, '2018-12-30 11:11:43');

$t->stop();
unlink("/tmp/dyupssocket");

##############################################################################
