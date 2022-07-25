local BasePlugin = require "kong.plugins.base_plugin"

local plugin = BasePlugin:extend()

plugin.PRIORITY = 100001 -- Run before the zipkin plugin to rewrite headers

function plugin:test(plugin_conf)
  ngx.exit(ngx.HTTP_NO_CONTENT)
end

function plugin:rewrite(plugin_conf)
  -- Delete all of the other tracing headers to stop other plugins interfearing or overwriting
  ngx.req.clear_header("b3")
  ngx.req.clear_header("x-b3-sampled")
  ngx.req.clear_header("x-b3-flags")
  ngx.req.clear_header("x-b3-traceid")
  ngx.req.clear_header("x-b3-spanid")
  ngx.req.clear_header("x-b3-parentspanid")
end

return plugin
