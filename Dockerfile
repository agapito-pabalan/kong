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

ARG AUTH0_JWKS_URL
ARG REDIS_CACHE_URL
ARG CLOUD_SIGNATURE_KEY
ARG CLOUD_SERVICE_URL
ARG LD_SDK_KEY
ARG OTEL_COLLECTOR_ENDPOINT

ARG SAIPH_URL
ARG RIGEL_URL
ARG USER_MANAGEMENT_URL
ARG MINTAKA_URL
ARG MEISSA_URL
ARG ORDERS_SERVICE_URL
ARG FACILITY_ACTIVITY_SERVICE_URL
ARG DOCUMENTS_SERVICE_URL
ARG INVENTORY_SERVICE_URL
ARG TRADE_PARTNERSHIPS_SERVICE_URL
ARG PRODUCT_CATALOG_SERVICE_URL
ARG HEALTHCHECK_AGGREGATOR_SERVICE_URL
ARG MARKETPLACE_SERVICE_URL
ARG TENANT_SERVICE_URL
ARG SEARCH_SERVICE_URL
ARG WMS_INTEGRATION_BRIDGE_URL
ARG TRANSPORTATION_SERVICE_URL
ARG ORDER_ORCHESTRATION_SERVICE_URL
ARG LOGIWA_READER_URL
ARG STORDBOT_URL
ARG PLANNING_SERVICE_URL

USER root

COPY --from=go-builder /go-plugins/user_management_bridge /usr/local/bin/user_management_bridge

COPY --from=lua-builder /lua-plugins/kong-plugin-traceheaders-1.0.0-0.all.rock /tmp
RUN luarocks install /tmp/kong-plugin-traceheaders-1.0.0-0.all.rock && rm /tmp/kong-plugin-traceheaders-1.0.0-0.all.rock

COPY kong.conf.d/kong.yml /usr/local/share/

RUN sed -i "s~AUTH0_JWKS_URL~$AUTH0_JWKS_URL~g" /usr/local/share/kong.yml && \
    sed -i "s~REDIS_CACHE_URL~$REDIS_CACHE_URL~g" /usr/local/share/kong.yml && \
    sed -i "s~CLOUD_SIGNATURE_KEY~$CLOUD_SIGNATURE_KEY~g" /usr/local/share/kong.yml && \
    sed -i "s~LD_SDK_KEY~$LD_SDK_KEY~g" /usr/local/share/kong.yml && \
    sed -i "s~OTEL_COLLECTOR_ENDPOINT~$OTEL_COLLECTOR_ENDPOINT~g" /usr/local/share/kong.yml && \
    sed -i "s~http://CLOUD_SERVICE_URL~$CLOUD_SERVICE_URL~g" /usr/local/share/kong.yml && \
    sed -i "s~http://SAIPH_URL~$SAIPH_URL~g" /usr/local/share/kong.yml && \
    sed -i "s~http://RIGEL_URL~$RIGEL_URL~g" /usr/local/share/kong.yml && \
    sed -i "s~http://USER_MANAGEMENT_URL~$USER_MANAGEMENT_URL~g" /usr/local/share/kong.yml && \
    sed -i "s~http://MINTAKA_URL~$MINTAKA_URL~g" /usr/local/share/kong.yml && \
    sed -i "s~http://MEISSA_URL~$MEISSA_URL~g" /usr/local/share/kong.yml && \
    sed -i "s~http://ORDERS_SERVICE_URL~$ORDERS_SERVICE_URL~g" /usr/local/share/kong.yml && \
    sed -i "s~http://FACILITY_ACTIVITY_SERVICE_URL~$FACILITY_ACTIVITY_SERVICE_URL~g" /usr/local/share/kong.yml && \
    sed -i "s~http://DOCUMENTS_SERVICE_URL~$DOCUMENTS_SERVICE_URL~g" /usr/local/share/kong.yml && \
    sed -i "s~http://INVENTORY_SERVICE_URL~$INVENTORY_SERVICE_URL~g" /usr/local/share/kong.yml && \
    sed -i "s~http://TRADE_PARTNERSHIPS_SERVICE_URL~$TRADE_PARTNERSHIPS_SERVICE_URL~g" /usr/local/share/kong.yml && \
    sed -i "s~http://PRODUCT_CATALOG_SERVICE_URL~$PRODUCT_CATALOG_SERVICE_URL~g" /usr/local/share/kong.yml && \
    sed -i "s~http://HEALTHCHECK_AGGREGATOR_SERVICE_URL~$HEALTHCHECK_AGGREGATOR_SERVICE_URL~g" /usr/local/share/kong.yml && \
    sed -i "s~http://MARKETPLACE_SERVICE_URL~$MARKETPLACE_SERVICE_URL~g" /usr/local/share/kong.yml && \
    sed -i "s~http://TENANT_SERVICE_URL~$TENANT_SERVICE_URL~g" /usr/local/share/kong.yml && \
    sed -i "s~http://SEARCH_SERVICE_URL~$SEARCH_SERVICE_URL~g" /usr/local/share/kong.yml && \
    sed -i "s~http://WMS_INTEGRATION_BRIDGE_URL~$WMS_INTEGRATION_BRIDGE_URL~g" /usr/local/share/kong.yml && \
    sed -i "s~http://TRANSPORTATION_SERVICE_URL~$TRANSPORTATION_SERVICE_URL~g" /usr/local/share/kong.yml && \
    sed -i "s~http://ORDER_ORCHESTRATION_SERVICE_URL~$ORDER_ORCHESTRATION_SERVICE_URL~g" /usr/local/share/kong.yml && \
    sed -i "s~http://LOGIWA_READER_URL~$LOGIWA_READER_URL~g" /usr/local/share/kong.yml && \
    sed -i "s~http://STORDBOT_URL~$STORDBOT_URL~g" /usr/local/share/kong.yml && \
    sed -i "s~http://PLANNING_SERVICE_URL~$PLANNING_SERVICE_URL~g" /usr/local/share/kong.yml

ENV KONG_DATABASE=off
ENV KONG_DECLARATIVE_CONFIG=/usr/local/share/kong.yml
ENV KONG_PLUGINS=user_management_bridge,cors,request-size-limiting,correlation-id,traceheaders,zipkin
ENV KONG_PLUGINSERVER_NAMES=user_management_bridge
ENV KONG_PLUGINSERVER_USER_MANAGEMENT_BRIDGE_START_CMD=/usr/local/bin/user_management_bridge
ENV KONG_PLUGINSERVER_USER_MANAGEMENT_BRIDGE_QUERY_CMD="/usr/local/bin/user_management_bridge -dump"

USER kong
