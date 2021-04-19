FROM golang:1.15-alpine as builder

WORKDIR /go-plugins

RUN apk add --no-cache git gcc libc-dev
RUN go mod init kong-go-plugin
RUN go get -d -v github.com/Kong/go-pdk
RUN go get -d -v github.com/Kong/go-pluginserver
RUN go get -d -v github.com/lestrrat-go/jwx/jwt
RUN go get -d -v github.com/lestrrat-go/jwx/jwk
RUN go get -d -v github.com/go-redis/redis/v8

COPY /plugins/bellatrix_bridge/bellatrix_bridge.go .
RUN go build github.com/Kong/go-pluginserver
RUN go build -buildmode plugin -o /go-plugins/bellatrix_bridge.so /go-plugins/bellatrix_bridge.go

FROM kong:2.2.1-alpine as release

ARG AUTH0_JWKS_URL
ARG REDIS_CACHE_URL
ARG SSL_CERTIFICATE_1
ARG SSL_CERTIFICATE_2
ARG SSL_CERTIFICATE_PRIVATE_KEY
ARG SNI_NAME
ARG KONG_TEMPLATE

ARG SAIPH_URL
ARG RIGEL_URL
ARG BELLATRIX_URL
ARG MINTAKA_URL
ARG MEISSA_URL
ARG ORDERS_SERVICE_URL

COPY --from=builder /go-plugins/go-pluginserver /usr/local/bin/
COPY --from=builder /go-plugins/bellatrix_bridge.so /usr/local/share/go-plugins/bellatrix_bridge.so

USER root

COPY kong.conf.d/$KONG_TEMPLATE /usr/local/share/
COPY kong.conf.d/kong.services.yml /usr/local/share/
RUN mv /usr/local/share/$KONG_TEMPLATE /usr/local/share/kong.yml
RUN cat /usr/local/share/kong.services.yml >> /usr/local/share/kong.yml

RUN sed -i "s~AUTH0_JWKS_URL~$AUTH0_JWKS_URL~g" /usr/local/share/kong.yml
RUN sed -i "s~REDIS_CACHE_URL~$REDIS_CACHE_URL~g" /usr/local/share/kong.yml
RUN sed -i "s~SSL_CERTIFICATE_1~$SSL_CERTIFICATE_1~g" /usr/local/share/kong.yml
RUN sed -i "s~SSL_CERTIFICATE_2~$SSL_CERTIFICATE_2~g" /usr/local/share/kong.yml
RUN sed -i "s~SSL_CERTIFICATE_PRIVATE_KEY~$SSL_CERTIFICATE_PRIVATE_KEY~g" /usr/local/share/kong.yml
RUN sed -i "s~SNI_NAME~$SNI_NAME~g" /usr/local/share/kong.yml

RUN sed -i "s~SAIPH_URL~$SAIPH_URL~g" /usr/local/share/kong.yml
RUN sed -i "s~RIGEL_URL~$RIGEL_URL~g" /usr/local/share/kong.yml
RUN sed -i "s~BELLATRIX_URL~$BELLATRIX_URL~g" /usr/local/share/kong.yml
RUN sed -i "s~MINTAKA_URL~$MINTAKA_URL~g" /usr/local/share/kong.yml
RUN sed -i "s~MEISSA_URL~$MEISSA_URL~g" /usr/local/share/kong.yml
RUN sed -i "s~ORDERS_SERVICE_URL~$ORDERS_SERVICE_URL~g" /usr/local/share/kong.yml

RUN chmod +r /usr/local/share/kong.yml

RUN apk add --update nodejs npm
RUN npm install --global yaml-validator
RUN yaml-validator /usr/local/share/kong.yml

USER kong 
