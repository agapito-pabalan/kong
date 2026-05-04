FROM golang:1.24.1-bullseye AS go-builder

WORKDIR /go-plugins

RUN apt-get update && apt-get install -y \
    binutils-gold \
    gcc \
    git \
    libc-dev \
    && rm -rf /var/lib/apt/lists/*

COPY /plugins/auth/go.mod /plugins/auth/go.sum ./
RUN go mod download

COPY /plugins/auth/auth.go .
RUN go build -o /go-plugins/auth /go-plugins/auth.go

FROM kong:3.9.1 AS release

USER root

RUN apt-get update && apt-get install -y \
    gettext \
    && rm -rf /var/lib/apt/lists/*

COPY --from=go-builder /go-plugins/auth /usr/local/bin/auth

COPY stord-entrypoint.sh /stord-entrypoint.sh

ENV KONG_ADMIN_ACCESS_LOG="/dev/stdout"
ENV KONG_ADMIN_ERROR_LOG="/dev/stderr"
ENV KONG_ADMIN_GUI_ACCESS_LOG="/dev/stdout"
ENV KONG_ADMIN_GUI_ERROR_LOG="/dev/stderr"
ENV KONG_ADMIN_LISTEN="0.0.0.0:8001"
ENV KONG_CLUSTER_LISTEN="off"
ENV KONG_DATABASE="off"
ENV KONG_DECLARATIVE_CONFIG="/usr/local/share/kong.yml"
ENV KONG_LUA_PACKAGE_PATH="/opt/?.lua;/opt/?/init.lua;;"
ENV KONG_NGINX_DAEMON="off"
ENV KONG_NGINX_HTTP_CLIENT_MAX_BODY_SIZE="0"
ENV KONG_NGINX_HTTP_PROXY_BUFFERS="16 32M"
ENV KONG_NGINX_HTTP_PROXY_BUFFER_SIZE="32M"
ENV KONG_NGINX_PROXY_CLIENT_BODY_BUFFER_SIZE="32M"
ENV KONG_NGINX_PROXY_CLIENT_HEADER_BUFFER_SIZE="64k"
ENV KONG_NGINX_PROXY_LARGE_CLIENT_HEADER_BUFFERS="8 64k"
ENV KONG_NGINX_WORKER_PROCESSES="2"
ENV KONG_PLUGINS="correlation-id,opentelemetry,auth,cors,request-size-limiting"
ENV KONG_PLUGINSERVER_NAMES="auth"
ENV KONG_PLUGINSERVER_AUTH_QUERY_CMD="/usr/local/bin/auth -dump"
ENV KONG_PLUGINSERVER_AUTH_START_CMD="/usr/local/bin/auth"
ENV KONG_PORTAL_API_ACCESS_LOG="/dev/stdout"
ENV KONG_PORTAL_API_ERROR_LOG="/dev/stderr"
ENV KONG_PORT_MAPS="80:8000"
ENV KONG_PROXY_ACCESS_LOG="/dev/stdout"
ENV KONG_PROXY_ERROR_LOG="/dev/stderr"
ENV KONG_PROXY_LISTEN="0.0.0.0:8000"
ENV KONG_STATUS_LISTEN="0.0.0.0:8100"
ENV KONG_STREAM_LISTEN="off"

COPY kong.conf.d/kong.yml /usr/local/share/

USER kong

ENTRYPOINT ["/stord-entrypoint.sh"]
