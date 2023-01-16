local policies = require "kong.plugins.quizizz-scalable-rate-limiter.policies"
local EXPIRATION = require "kong.plugins.quizizz-scalable-rate-limiter.expiration"
local timestamp = require "kong.tools.timestamp"
local metrics = require "kong.plugins.quizizz-scalable-rate-limiter.metrics"

local kong = kong
local ngx = ngx
local time = ngx.time
local pairs = pairs
local tostring = tostring
local timer_at = ngx.timer.at
local max = math.max
local floor = math.floor
local cjson = require "cjson"

local EMPTY = {}

local RATELIMIT_LIMIT     = "RateLimit-Limit"
local RATELIMIT_REMAINING = "RateLimit-Remaining"
local RATELIMIT_RESET     = "RateLimit-Reset"
local RETRY_AFTER         = "Retry-After"
local RATELIMIT_EXCEEDED  = "RateLimit-Exceeded"


local X_RATELIMIT_LIMIT = {
  second = "X-RateLimit-Limit-Second",
  minute = "X-RateLimit-Limit-Minute",
  hour   = "X-RateLimit-Limit-Hour",
  day    = "X-RateLimit-Limit-Day",
  month  = "X-RateLimit-Limit-Month",
  year   = "X-RateLimit-Limit-Year",
}

local X_RATELIMIT_REMAINING = {
  second = "X-RateLimit-Remaining-Second",
  minute = "X-RateLimit-Remaining-Minute",
  hour   = "X-RateLimit-Remaining-Hour",
  day    = "X-RateLimit-Remaining-Day",
  month  = "X-RateLimit-Remaining-Month",
  year   = "X-RateLimit-Remaining-Year",
}

local RateLimitingHandler = {}

RateLimitingHandler.VERSION = "2.2.0"
RateLimitingHandler.PRIORITY = tonumber(os.getenv("PRIORITY_SCALABLE_RATE_LIMITER")) or 960
kong.log.info("Plugin priority set to " .. RateLimitingHandler.PRIORITY .. (os.getenv("PRIORITY_SCALABLE_RATE_LIMITER") and " from env" or " by default"))

local function remove_last_ip(ips)
    local _, ip_count = string.gsub(ips, " ", "")
    ip_count = ip_count + 1

    local new_identifier = ""
    local j = 0
    for i in string.gmatch(ips, "%S+") do
        if j == ip_count - 1 then
            break
        end
        j = j + 1
        new_identifier = new_identifier .. ":" .. i
    end

    return new_identifier
end

local function get_cookie(cookies, cookie_name)
    local t={}
    for str in string.gmatch(cookies, "([^ ]+)") do
        local cookie_temp = {}
        for i in string.gmatch(str, "([^=]+)") do
            table.insert(cookie_temp, i)
        end
        if cookie_temp[1] == cookie_name then
            return cookie_temp[2]
        end
    end

    return nil
end

local function get_identifier(conf)
    local identifier

    if conf.limit_by == "service" then
        identifier = (kong.router.get_service() or EMPTY).id
    elseif conf.limit_by == "header" then
        if conf.header_name == "x-forwarded-for" and kong.request.get_header(conf.header_name) ~= nil then
            identifier = remove_last_ip(kong.request.get_header(conf.header_name))
        else
            identifier = kong.request.get_header(conf.header_name)
        end
    elseif conf.limit_by == "consumer" then
        identifier = kong.request.get_header("X-Consumer-Username")
    elseif conf.limit_by == "cookie" then
        local cookies = kong.request.get_header("cookie")
        if cookies ~= nil then
            identifier = get_cookie(cookies, conf.cookie_name)
        end
    end

    if not identifier then
        return nil, "No rate-limiting identifier found in request"
    end

    return identifier or kong.client.get_forwarded_ip()
end

local function get_usage(conf, identifier, current_timestamp, limits)
    local usage = {}
    local stop

    for period, limit in pairs(limits) do
        local current_usage, err = policies[conf.policy].usage(conf, identifier, period, current_timestamp)
        if err then
            return nil, nil, err
        end

        current_usage = current_usage or 0

        -- What is the current usage for the configured limit name?
        local remaining = limit - current_usage

        -- Recording usage
        usage[period] = {
            limit = limit,
            remaining = remaining
        }

        if remaining <= 0 then
            stop = period
        end
    end

    return usage, stop
end

local function increment(premature, conf, ...)
    if premature then
        return
    end
    policies[conf.policy].increment(conf, ...)
end

local function populate_client_headers(conf, limits_per_consumer)
    local status = true
    if not conf.hide_client_headers then
        if conf.limit_by == "consumer" and limits_per_consumer == nil then
            status = false
        end
    end
    return status
end

local function check_auth(conf)
    if not conf.disable_on_auth then
        kong.log.info("Disable on auth is false.")
        return true
    end

    if conf.auth_type == 'cookie' then
        local cookies = kong.request.get_header("cookie")
        if cookies ~= nil then
            kong.log.info("Cookie result", get_cookie(cookies, conf.auth_cookie))
            local auth_invalid = get_cookie(cookies, conf.auth_cookie) == nil
            kong.log.info("disable on auth was true. Auth invalidity - ", auth_invalid)
            return auth_invalid
        else
            kong.log.info("No cookies found, disable on auth was true and auth is invalid")
            return true
        end

    else
        kong.log.err('Invalid auth type, ', conf.auth_type, '. disable on auth was true and auth is invalid and auth validity failed')
        return true
    end
end

function RateLimitingHandler:init_worker(conf)
    metrics.init()
end

function RateLimitingHandler:access(conf)
    local current_timestamp = time() * 1000

    -- Consumer is identified by ip address or authenticated_credential id
    local identifier, err = get_identifier(conf)

    if err then
        kong.log.err(err)
        return
    end

    -- Load current metric for configured period
    local limits = {
        second = conf.second,
        minute = conf.minute,
        hour = conf.hour,
        day = conf.day
    }

    local limits_per_consumer
    if conf.limit_by == "consumer" then
        limits_per_consumer = cjson.decode(conf.limit_by_consumer_config)[kong.request.get_header("X-Consumer-Username")]
        if limits_per_consumer ~= nil then
            limits = limits_per_consumer
        end
    end

    local usage, stop, err = get_usage(conf, identifier, current_timestamp, limits)

    if err then
        kong.log.err("failed to get usage: ", tostring(err))
    end

    kong.log.info("Identifier - ", identifier, limits)

    if check_auth(conf) and usage then
        -- Adding headers
        local reset
        local headers
        if populate_client_headers then
          headers = {}
          local timestamps
          local limit
          local window
          local remaining
          for k, v in pairs(usage) do
            local current_limit = v.limit
            local current_window = EXPIRATION[k]
            local current_remaining = v.remaining
            if stop == nil or stop == k then
              current_remaining = current_remaining - 1
            end
            current_remaining = max(0, current_remaining)

            if not limit or (current_remaining < remaining)
                         or (current_remaining == remaining and
                             current_window > window)
            then
              limit = current_limit
              window = current_window
              remaining = current_remaining

              if not timestamps then
                timestamps = timestamp.get_timestamps(current_timestamp)
              end

              reset = max(1, window - floor((current_timestamp - timestamps[k]) / 1000))
            end

            headers[X_RATELIMIT_LIMIT[k]] = current_limit
            headers[X_RATELIMIT_REMAINING[k]] = current_remaining
          end

          headers[RATELIMIT_LIMIT] = limit
          headers[RATELIMIT_REMAINING] = remaining
          headers[RATELIMIT_RESET] = reset
        end

        metrics.increment_counter(
            conf.rate_limiter_name,
            conf.limit_by,
            kong.router.get_route()['name'],
            kong.router.get_service()['name']
        )

        -- If get_usage succeeded and limit has been crossed
        if usage and stop then
            headers = headers or {}

            if conf.shadow_mode_enabled then
                if conf.shadow_mode_include_response_header then
                    headers[conf.shadow_mode_response_header_name] = true
                end
                if conf.shadow_mode_verbose_logging then
                    kong.log.warn("Rate limit exceeded for identifier ", identifier)
                end
            else
                kong.log.err("API rate limit exceeded")
                headers[RETRY_AFTER] = reset
                return kong.response.exit(429, { error = { message = conf.error_message }}, headers)
            end

        end

        if headers then
            kong.response.set_headers(headers)
        end
    end

    kong.ctx.plugin.timer = function()
        local ok, err = timer_at(0, increment, conf, limits, identifier, current_timestamp, 1)
        if not ok then
            kong.log.err("failed to create timer: ", err)
        end
    end
end

function RateLimitingHandler:log(_)
    if kong.ctx.plugin.timer then
        kong.ctx.plugin.timer()
    end
end

return RateLimitingHandler
