FROM ubuntu:trusty
MAINTAINER Yves-Marie Saout « chatov42@gmail.com »

# install LuaJIT
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y install openssl libssl-dev zlib1g zlib1g-dev git curl tar make build-essential debhelper autoconf automake patch dpkg-dev fakeroot pbuilder vim && \
    cd /usr/local/src && \
    curl -O http://luajit.org/download/LuaJIT-2.0.3.tar.gz && \
    tar xf LuaJIT-2.0.3.tar.gz && \
    cd LuaJIT-2.0.3 && \
    make && \
    make PREFIX=/usr/local/luajit install

# install nginx with lua-nginx-module
    RUN useradd --no-create-home nginx
    RUN export LUAJIT_LIB=/usr/local/luajit/lib && \
    export LUAJIT_INC=/usr/local/luajit/include/luajit-2.0 && \
    cd /usr/local/src && \
    git clone git://github.com/simpl/ngx_devel_kit.git && \
    git clone git://github.com/openresty/echo-nginx-module.git && \
    git clone git://github.com/chaoslawful/lua-nginx-module.git && \
    git clone git://github.com/yzprofile/ngx_http_dyups_module.git && \
    curl -LO http://downloads.sourceforge.net/project/pcre/pcre/8.35/pcre-8.35.tar.bz2 && \
    tar xf pcre-8.35.tar.bz2 && \
    git clone git://github.com/alibaba/tengine.git && \
    cd tengine && \
    wget https://raw.githubusercontent.com/yzprofile/ngx_http_dyups_module/master/upstream_check-tengine-2.0.3.patch && \
    git apply upstream_check-tengine-2.0.3.patch && \
    ./configure \
        --prefix=/etc/nginx \
        --sbin-path=/usr/sbin/nginx \
        --conf-path=/etc/nginx/nginx.conf \
        --error-log-path=/var/log/nginx/error.log \
        --http-log-path=/var/log/nginx/access.log \
        --pid-path=/var/run/nginx.pid \
        --lock-path=/var/run/nginx.lock \
        --group=nginx \
        --with-http_ssl_module \
        --with-http_realip_module \
        --with-http_addition_module \
        --with-http_sub_module \
        --with-http_dav_module \
        --with-http_flv_module \
        --with-http_mp4_module \
        --with-http_gunzip_module \
        --with-http_gzip_static_module \
        --with-http_random_index_module \
        --with-http_secure_link_module \
        --with-http_stub_status_module \
        --with-mail \
        --with-mail_ssl_module \
        --with-file-aio \
        --with-ipv6 \
        --with-pcre=/usr/local/src/pcre-8.35 \
        --add-module=/usr/local/src/ngx_devel_kit \
        --add-module=/usr/local/src/echo-nginx-module \
        --add-module=/usr/local/src/lua-nginx-module \
        --add-module=/usr/local/src/ngx_http_dyups_module \
        --with-ld-opt="-Wl,-rpath,$LUAJIT_LIB" && \
    make && \
    make install

ADD nginx.conf /etc/nginx/nginx.conf
ADD upstream.conf /etc/nginx/conf/upstream.conf

EXPOSE 80
CMD ["/usr/sbin/nginx", "-g", "daemon off;"]
