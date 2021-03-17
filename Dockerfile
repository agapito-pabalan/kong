FROM golang:1.15-alpine as builder

RUN apk add --no-cache git gcc libc-dev
RUN go get github.com/Kong/go-pluginserver
RUN go get github.com/lestrrat-go/jwx/jwt
RUN go get github.com/lestrrat-go/jwx/jwk
RUN go get github.com/go-redis/redis

RUN mkdir /go-plugins
COPY /plugins/bellatrix_bridge/bellatrix_bridge.go /go-plugins/bellatrix_bridge.go
RUN go build -buildmode plugin -o /go-plugins/bellatrix_bridge.so /go-plugins/bellatrix_bridge.go

FROM kong:2.2.1-alpine as release

ARG REDIS_CACHE_URL
ARG SSL_CERTIFICATE_1
ARG SSL_CERTIFICATE_2
ARG SSL_CERTIFICATE_PRIVATE_KEY
ARG SNI_NAME

COPY --from=builder /go/bin/go-pluginserver /usr/local/bin/go-pluginserver
COPY --from=builder /go-plugins/bellatrix_bridge.so /usr/local/share/go-plugins/bellatrix_bridge.so
COPY kong.conf.d/kong.template.yml /usr/local/share/kong.yml

USER root

RUN sed -i "s~AUTH0_JWKS_URL~$AUTH0_JWKS_URL~g" /usr/local/share/kong.yml
RUN sed -i "s~REDIS_CACHE_URL~$REDIS_CACHE_URL~g" /usr/local/share/kong.yml
RUN sed -i "s~SSL_CERTIFICATE_1~$SSL_CERTIFICATE_1~g" /usr/local/share/kong.yml
RUN sed -i "s~SSL_CERTIFICATE_2~$SSL_CERTIFICATE_2~g" /usr/local/share/kong.yml
RUN sed -i "s~SSL_CERTIFICATE_PRIVATE_KEY~$SSL_CERTIFICATE_PRIVATE_KEY~g" /usr/local/share/kong.yml
RUN sed -i "s~SNI_NAME~$SNI_NAME~g" /usr/local/share/kong.yml

RUN chmod +r /usr/local/share/kong.yml

USER kong 
