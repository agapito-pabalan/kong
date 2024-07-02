FROM golang:1.21-alpine as go-builder

WORKDIR /go-plugins

RUN apk add --no-cache git gcc libc-dev binutils-gold
RUN go mod init kong-go-plugin
RUN go get -d -v github.com/Kong/go-pdk@v0.8.0
RUN go get -d -v github.com/Kong/go-pdk/server@v0.8.0
RUN go get -d -v github.com/lestrrat-go/jwx/jwt
RUN go get -d -v github.com/lestrrat-go/jwx/jwk
RUN go get -d -v github.com/go-redis/redis/v8
RUN go get github.com/launchdarkly/go-sdk-common/v3/ldcontext
RUN go get github.com/launchdarkly/go-server-sdk/v7

COPY /plugins/user_management_bridge/user_management_bridge.go .
RUN go build  -o /go-plugins/user_management_bridge /go-plugins/user_management_bridge.go

FROM kong:2.7.2-alpine as lua-builder

WORKDIR /lua-plugins

USER root

COPY /plugins/traceheaders .
RUN luarocks make && luarocks pack kong-plugin-traceheaders 1.0.0-0

FROM kong:2.7.2-alpine as release

USER root

RUN apk add --no-cache gettext

COPY --from=go-builder /go-plugins/user_management_bridge /usr/local/bin/user_management_bridge

COPY --from=lua-builder /lua-plugins/kong-plugin-traceheaders-1.0.0-0.all.rock /tmp
RUN luarocks install /tmp/kong-plugin-traceheaders-1.0.0-0.all.rock && rm /tmp/kong-plugin-traceheaders-1.0.0-0.all.rock

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
ENV KONG_PLUGINS="user_management_bridge,cors,request-size-limiting,correlation-id,traceheaders,zipkin"
ENV KONG_PLUGINSERVER_NAMES="user_management_bridge"
ENV KONG_PLUGINSERVER_USER_MANAGEMENT_BRIDGE_QUERY_CMD="/usr/local/bin/user_management_bridge -dump"
ENV KONG_PLUGINSERVER_USER_MANAGEMENT_BRIDGE_START_CMD="/usr/local/bin/user_management_bridge"
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
