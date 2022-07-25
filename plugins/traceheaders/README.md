# kong-traceheaders

This is a very simple plugin that deletes B3 trace headers. This is due to the way Istio propagates trace headers, and includes `B3` along with the `traceparent` header. This causes Kong to detect and use the `B3` header instead of the `traceparent`. The solution? Just remove the `B3` header before Kong does any tracing.

Before starting anything, it's highly recommended to read the [Kong plugin development documentation](https://docs.konghq.com/gateway-oss/1.4.x/plugin-development/).

## Setup

We use [kong-pongo](https://github.com/Kong/kong-pongo) to work with this package. This lets us isolate plugin logic from all of the other plugins we normally ship in our kong image.

You can follow the [installation instructions on their README](https://github.com/Kong/kong-pongo#installation).

## Q/A

Q: Why not use the [Request Transformer](https://docs.konghq.com/hub/kong-inc/request-transformer/) plugin to do this? Seems simpler.

A: Plugin Priority. The request transformer plugin does not run before the Zipkin plugin. Sadly this can't be changed as a user setting.

## Testing

Run `pongo run`.

## Linting

Run `pongo lint`.
