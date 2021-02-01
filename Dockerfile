FROM golang:alpine as builder

RUN apk add --no-cache git gcc libc-dev
RUN go get github.com/Kong/go-pluginserver

RUN mkdir /go-plugins
COPY /plugins/bellatrix_bridge/bellatrix_bridge.go /go-plugins/bellatrix_bridge.go
RUN go build -buildmode plugin -o /go-plugins/bellatrix_bridge.so /go-plugins/bellatrix_bridge.go

FROM kong:2.2.1-alpine as release

ARG KONG_DATABASE
ARG KONG_DECLARATIVE_CONFIG
ARG KONG_ADMIN_LISTEN
ARG KONG_PROXY_LISTEN
ARG KONG_PLUGINS
ARG KONG_GO_PLUGINS_DIR
ARG KONG_PROXY_ACCESS_LOG
ARG KONG_PROXY_ERROR_LOG
ARG KONG_ADMIN_ACCESS_LOG
ARG KONG_ADMIN_ERROR_LOG
ARG KONG_LOG_LEVEL
ARG SSL_CERTIFICATE_1
ARG SSL_CERTIFICATE_2
ARG SSL_CERTIFICATE_PRIVATE_KEY
ARG SNI_NAME

COPY --from=builder /go/bin/go-pluginserver /usr/local/bin/go-pluginserver
COPY --from=builder /go-plugins/bellatrix_bridge.so /usr/local/share/go-plugins/bellatrix_bridge.so
COPY kong.conf.d/kong.template.yml /usr/local/share/kong.yml

USER root

RUN sed -i "s~SSL_CERTIFICATE_1~$SSL_CERTIFICATE_1~g" /usr/local/share/kong.yml
RUN sed -i "s~SSL_CERTIFICATE_2~$SSL_CERTIFICATE_2~g" /usr/local/share/kong.yml
RUN sed -i "s~SSL_CERTIFICATE_PRIVATE_KEY~$SSL_CERTIFICATE_PRIVATE_KEY~g" /usr/local/share/kong.yml
RUN sed -i "s~SNI_NAME~$SNI_NAME~g" /usr/local/share/kong.yml

RUN chmod +r /usr/local/share/kong.yml

USER kong 
