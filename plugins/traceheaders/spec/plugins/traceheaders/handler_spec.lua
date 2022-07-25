local helpers = require "spec.helpers"

local PLUGIN_NAME = "traceheaders"

for _, strategy in helpers.each_strategy() do
  describe("Plugin: " .. PLUGIN_NAME .. " (handler) [#" .. strategy .. "]", function()
    local client

    lazy_setup(function()
      local bp = helpers.get_db_utils(strategy == "off" and "postgres" or strategy, nil, { PLUGIN_NAME })

      bp.plugins:insert {
        name = PLUGIN_NAME
      }

      bp.plugins:insert {
        name = "zipkin",
        config = {
          sample_ratio = 1,
          include_credential = false,
          traceid_byte_count = 16,
          header_type = "w3c",
        }
      }

      local route1 = bp.routes:insert({
        hosts = { "test1.com" },
      })

      assert(helpers.start_kong({
        database   = strategy,
        nginx_conf = "spec/fixtures/custom_nginx.template",
        plugins = "bundled," .. PLUGIN_NAME .. ",zipkin",
        declarative_config = helpers.make_yaml_file(),
        pg_host = nil,
        cassandra_contact_points = nil,
      }))
    end)

    lazy_teardown(function()
      helpers.stop_kong(nil, true)
    end)

    before_each(function()
      client = helpers.proxy_client()
    end)

    after_each(function()
      if client then client:close() end
    end)

    it("removes b3 headers to avoid overwrite", function()
      local r = client:get("/request", {
        headers = {
          host = "test1.com",
          b3 = "0000008c3defb1edb984fe2ac71c71c7-0007e5196e2ae38e-1",
        }
      })

      assert.response(r).has.status(200)
      local header = assert.request(r).has.header("traceparent")
      assert(header:find("-0000008c3defb1edb984fe2ac71c71c7-"))

      assert.request(r).has_not.header("b3")
    end)
  end)
end
