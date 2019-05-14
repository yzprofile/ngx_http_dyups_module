use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use File::Path;
use Test::Nginx;

use lib $FindBin::Bin;
use mhttp;

my $t = Test::Nginx->new()->plan(4);

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

warn "your test dir is ".$t->testdir();

##############################################################################

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

worker_processes auto;

events {
    accept_mutex off;
}

http {

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

        location /lua/add {
            content_by_lua '
            local dyups = require "ngx.dyups"
            local status, rv = dyups.update("dyhost", [[server 127.0.0.1:8088;]]);
            ngx.print(status, rv)
            ';
        }

        location /lua/delete {
            content_by_lua '
            local dyups = require "ngx.dyups"
            local status, rv = dyups.delete("dyhost");
            ngx.print(status, rv)
            ';
        }
    }
}
EOF

mrun($t);


like(mhttp_get('/lua/add', 'localhost', 8081), qr/200success/m, '5/ 5 11:04:49 2014');
sleep(1);
like(mhttp_get('/', 'dyhost', 8080), qr/8088/m, '5/ 5 11:04:42 2014');

like(mhttp_get('/lua/delete', 'localhost', 8081), qr/200success/m, '5/ 5 11:08:08 2014');
sleep(1);
like(mhttp_get('/', 'dyhost', 8080), qr/502/m, '5/ 5 11:08:16 2014');


$t->stop();
unlink("/tmp/dyupssocket");

# ###############################################################################
