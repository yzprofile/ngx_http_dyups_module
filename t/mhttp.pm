package mhttp;

use strict;
use warnings;
use Exporter;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use File::Path;
use Test::Nginx;

our @ISA= qw( Exporter );

our @EXPORT = qw( mrun mhttp_get mhttp_post mhttp_delete );

sub mrun($;$) {
    my ($self, $conf) = @_;

    my $testdir = $self->{_testdir};

    my $ngx = defined $ENV{TEST_NGINX_BINARY} 
            ? $ENV{TEST_NGINX_BINARY}
            : '../nginx/objs/nginx';

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
        exec($ngx, '-c', "$testdir/nginx.conf", '-p', "$testdir",
             @globals) or die "Unable to exec(): $!\n";
    }

    # wait for nginx to start

    $self->waitforfile("$testdir/nginx.pid")
        or die "Can't start nginx";

    $self->{_started} = 1;
    return $self;
}

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

sub mhttp($;$;%) {
    my ($request, $port, %extra) = @_;
    my $reply;
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        local $SIG{PIPE} = sub { die "sigpipe\n" };
        alarm(20);
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