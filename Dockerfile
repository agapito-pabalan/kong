FROM golang:1.15-alpine as builder

WORKDIR /go-plugins

RUN apk add --no-cache git gcc libc-dev
RUN go mod init kong-go-plugin
RUN go get -d -v github.com/Kong/go-pdk
RUN go get -d -v github.com/Kong/go-pluginserver
RUN go get -d -v github.com/lestrrat-go/jwx/jwt
RUN go get -d -v github.com/lestrrat-go/jwx/jwk
RUN go get -d -v github.com/go-redis/redis/v8

COPY /plugins/user_management_bridge/user_management_bridge.go .
RUN go build github.com/Kong/go-pluginserver
RUN go build -buildmode plugin -o /go-plugins/user_management_bridge.so /go-plugins/user_management_bridge.go

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
ARG USER_MANAGEMENT_URL
ARG MINTAKA_URL
ARG MEISSA_URL
ARG ORDERS_SERVICE_URL
ARG FACILITY_ACTIVITY_SERVICE_URL
ARG DOCUMENTS_SERVICE_URL
ARG ITEM_SERVICE_URL
ARG TRADE_PARTNERSHIPS_SERVICE_URL
ARG PRODUCT_CATALOG_SERVICE_URL

COPY --from=builder /go-plugins/go-pluginserver /usr/local/bin/
COPY --from=builder /go-plugins/user_management_bridge.so /usr/local/share/go-plugins/user_management_bridge.so

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

RUN sed -i "s~http://SAIPH_URL~$SAIPH_URL~g" /usr/local/share/kong.yml
RUN sed -i "s~http://RIGEL_URL~$RIGEL_URL~g" /usr/local/share/kong.yml
RUN sed -i "s~http://USER_MANAGEMENT_URL~$USER_MANAGEMENT_URL~g" /usr/local/share/kong.yml
RUN sed -i "s~http://MINTAKA_URL~$MINTAKA_URL~g" /usr/local/share/kong.yml
RUN sed -i "s~http://MEISSA_URL~$MEISSA_URL~g" /usr/local/share/kong.yml
RUN sed -i "s~http://ORDERS_SERVICE_URL~$ORDERS_SERVICE_URL~g" /usr/local/share/kong.yml
RUN sed -i "s~http://FACILITY_ACTIVITY_SERVICE_URL~$FACILITY_ACTIVITY_SERVICE_URL~g" /usr/local/share/kong.yml
RUN sed -i "s~http://DOCUMENTS_SERVICE_URL~$DOCUMENTS_SERVICE_URL~g" /usr/local/share/kong.yml
RUN sed -i "s~http://ITEM_SERVICE_URL~$ITEM_SERVICE_URL~g" /usr/local/share/kong.yml
RUN sed -i "s~http://TRADE_PARTNERSHIPS_SERVICE_URL~$TRADE_PARTNERSHIPS_SERVICE_URL~g" /usr/local/share/kong.yml
RUN sed -i "s~http://PRODUCT_CATALOG_SERVICE_URL~$PRODUCT_CATALOG_SERVICE_URL~g" /usr/local/share/kong.yml

RUN chmod +r /usr/local/share/kong.yml

RUN apk add --update nodejs npm
RUN npm install --global yaml-validator
RUN yaml-validator /usr/local/share/kong.yml

USER kong
