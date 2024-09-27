#!/bin/bash

export KONG_DECLARATIVE_CONFIG=${KONG_DECLARATIVE_CONFIG:-"/etc/kong/kong.yaml"}

# Manually run envsubst on the kong.yaml file to
# interpolate environment variables. Our super simple
# stupid way to allow environment variables in the kong.yaml
# file.
envsubst < ${KONG_DECLARATIVE_CONFIG} > /tmp/kong.interpolated.yaml
export KONG_DECLARATIVE_CONFIG=/tmp/kong.interpolated.yaml

touch /tmp/auth.log


exec /bin/sh -c "tail -f /tmp/auth.log & /docker-entrypoint.sh kong docker-start"
