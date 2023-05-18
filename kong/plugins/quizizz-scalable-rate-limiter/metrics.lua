local exporter = require('kong.plugins.prometheus.exporter')

local kong = kong
local table_new = kong.table.new
local get_prometheus = exporter.get_prometheus

local register = table_new(0, 3)

local function init()
  local prometheus = get_prometheus()
  register.kong_request_ratelimit_reached = prometheus:counter(
    'quizizz_kong_request_rate_limited'
  , 'total requests that have reached a rate limit threshold'
  , {'rate_limiter_name', 'limited_by', 'service', 'route', 'identifier'}
  )

  return register
end

local function increment_counter(rate_limiter_name, limited_by, service, route, identifier)
  register.kong_request_ratelimit_reached:inc(1, {rate_limiter_name, limited_by, service, route, identifier})

end

return {
  init = init,
  increment_counter = increment_counter
}
