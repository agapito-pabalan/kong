FROM golang:alpine as builder

RUN apk add --no-cache git gcc libc-dev
RUN go get github.com/Kong/go-pluginserver

RUN mkdir /go-plugins
COPY /plugins/bellatrix_bridge/bellatrix_bridge.go /go-plugins/bellatrix_bridge.go
RUN go build -buildmode plugin -o /go-plugins/bellatrix_bridge.so /go-plugins/bellatrix_bridge.go

FROM kong:2.0.4-alpine

COPY --from=builder /go/bin/go-pluginserver /usr/local/bin/go-pluginserver
RUN mkdir /tmp/go-plugins
COPY --from=builder /go-plugins/bellatrix_bridge.so /tmp/go-plugins/bellatrix_bridge.so
COPY kong.conf.d/config.yml /tmp/config.yml

USER root
RUN chmod -R 777 /tmp
USER kong
