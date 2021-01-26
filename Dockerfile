FROM golang:alpine as builder

RUN apk add --no-cache git gcc libc-dev
RUN go get github.com/Kong/go-pluginserver
RUN go get github.com/rs/zerolog

RUN mkdir /go-plugins
COPY /plugins/bellatrix_bridge/bellatrix_bridge.go /go-plugins/bellatrix_bridge.go
RUN go build -buildmode plugin -o /go-plugins/bellatrix_bridge.so /go-plugins/bellatrix_bridge.go

FROM kong:2.0.4-alpine as release

ARG KONG_DATABASE
ARG KONG_DECLARATIVE_CONFIG
ARG KONG_ADMIN_LISTEN
ARG KONG_PLUGINS
ARG KONG_GO_PLUGINS_DIR
ARG KONG_PROXY_ACCESS_LOG
ARG KONG_PROXY_ERROR_LOG
ARG KONG_ADMIN_ACCESS_LOG
ARG KONG_ADMIN_ERROR_LOG
ARG KONG_LOG_LEVEL

COPY --from=builder /go/bin/go-pluginserver /usr/local/bin/go-pluginserver
COPY --from=builder /go-plugins/bellatrix_bridge.so /usr/local/share/go-plugins/bellatrix_bridge.so
COPY kong.conf.d/config.yml /usr/local/share/config.yml

USER root
RUN chmod -R 777 /tmp
USER kong
