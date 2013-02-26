use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }


use lib 'lib';
use File::Path;
use Test::Nginx;


my $NGINX = defined $ENV{TEST_NGINX_BINARY} ? $ENV{TEST_NGINX_BINARY}
        : '../nginx/objs/nginx';
my $t = Test::Nginx->new()->plan(5);

sub mhttp_get($;$;$;%) {
    my ($url, $host, $port, %extra) = @_;
    return mhttp(<<EOF, $port, %extra);
GET $url HTTP/1.0
Host: $host

EOF
}

sub mhttp_post($;$;$;%) {
    my ($url, $body, $port, %extra) = @_;
    my $len = length($body);
    return mhttp(<<EOF, $port, %extra);
POST $url HTTP/1.0
Host: localhost
Content-Length: $len

$body
EOF
}


sub mhttp_delete($;$;%) {
    my ($url, $port, %extra) = @_;
    return mhttp(<<EOF, $port, %extra);
DELETE $url HTTP/1.0
Host: localhost

EOF
}


sub mrun($;$) {
    my ($self, $conf) = @_;

    my $testdir = $self->{_testdir};

    if (defined $conf) {
        my $c = `cat $conf`;
        $self->write_file_expand('nginx.conf', $c);
    }

    my $pid = fork();
    die "Unable to fork(): $!\n" unless defined $pid;

    if ($pid == 0) {
        my @globals = $self->{_test_globals} ?
            () : ('-g', "pid $testdir/nginx.pid; "
                  . "error_log $testdir/error.log debug;");
        exec($NGINX, '-c', "$testdir/nginx.conf", '-p', "$testdir",
             @globals) or die "Unable to exec(): $!\n";
    }

    # wait for nginx to start

    $self->waitforfile("$testdir/nginx.pid")
        or die "Can't start nginx";

    $self->{_started} = 1;
    return $self;
}

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

warn "your test dir is ".$t->testdir();

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
    accept_mutex off;
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
    
    limit_req_zone $binary_remote_addr zone=one:10m rate=1r/s;
    server {
        listen 8088;
        location / {
            limit_req zone=one burst=1000;
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
EOF

mrun($t);

###############################################################################
my $rep;
my $body;

$rep = qr/
host1
host2
/m;
like(mhttp_get('/list', 'localhost', 8081), $rep, 'dyups hello');

like(mhttp_post('/upstream/dyhost', 'server 127.0.0.1:8088;', 8081), qr/success/m, 'dyups hello post');
like(mhttp_get('/', 'dyhost', 8080), qr/8088/m, 'dyups hello');

like(mhttp_delete('/upstream/dyhost', 8081), qr/success/m, 'dyups hello delete');
like(mhttp_get('/', 'dyhost', 8080), qr/502/m, 'dyups hello');

$t->stop();



##############################################################################

sub mhttp($;$;%) {
    my ($request, $port, %extra) = @_;
    my $reply;
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        local $SIG{PIPE} = sub { die "sigpipe\n" };
        alarm(2);
        my $s = IO::Socket::INET->new(
            Proto => "tcp",
            PeerAddr => "127.0.0.1:$port"
            );
        log_out($request);
        $s->print($request);
        local $/;
        select undef, undef, undef, $extra{sleep} if $extra{sleep};
        return '' if $extra{aborted};
        $reply = $s->getline();
        alarm(0);
    };
    alarm(0);
    if ($@) {
        log_in("died: $@");
        return undef;
    }
    log_in($reply);
    return $reply;
}
