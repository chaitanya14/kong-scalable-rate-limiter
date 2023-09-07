local policies = require "kong.plugins.quizizz-scalable-rate-limiter.policies"
local EXPIRATION = require "kong.plugins.quizizz-scalable-rate-limiter.expiration"
local timestamp = require "kong.tools.timestamp"
local metrics = require "kong.plugins.quizizz-scalable-rate-limiter.metrics"
local iputils = require "kong.plugins.quizizz-scalable-rate-limiter.iputils"
local httputils = require "kong.plugins.quizizz-scalable-rate-limiter.httputils"

local kong = kong
local ngx = ngx
local time = ngx.time
local pairs = pairs
local tostring = tostring
local timer_at = ngx.timer.at
local max = math.max
local floor = math.floor
local cjson = require "cjson"
local luatz = require "luatz"
local gettime = luatz.gettime

local EMPTY = {}

local RATELIMIT_LIMIT     = "RateLimit-Limit"
local RATELIMIT_REMAINING = "RateLimit-Remaining"
local RATELIMIT_RESET     = "RateLimit-Reset"
local RETRY_AFTER         = "Retry-After"
local RATELIMITERS_APPLIED = "X-RateLimits-Applied"
local WHITELISTED_IP_HEADER = "X-Whitelisted-IP"

local DEVICEID_WEB_COOKIE = "quizizz_uid"
local DEVICEID_APP_COOKIE = "Q_HTTP_USER_DEVICE_ID"

local X_RATELIMIT_LIMIT = {
  second = "RateLimit-Limit-Second",
  minute = "RateLimit-Limit-Minute",
  hour   = "RateLimit-Limit-Hour",
  day    = "RateLimit-Limit-Day",
  month  = "RateLimit-Limit-Month",
  year   = "RateLimit-Limit-Year",
}

local X_RATELIMIT_REMAINING = {
  second = "RateLimit-Remaining-Second",
  minute = "RateLimit-Remaining-Minute",
  hour   = "RateLimit-Remaining-Hour",
  day    = "RateLimit-Remaining-Day",
  month  = "RateLimit-Remaining-Month",
  year   = "RateLimit-Remaining-Year",
}

local RateLimitingHandler = {}

RateLimitingHandler.VERSION = "2.2.0"
RateLimitingHandler.PRIORITY = tonumber(os.getenv("PRIORITY_SCALABLE_RATE_LIMITER")) or 960
kong.log.info("Plugin priority set to " .. RateLimitingHandler.PRIORITY .. (os.getenv("PRIORITY_SCALABLE_RATE_LIMITER") and " from env" or " by default"))

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

local function get_identifier(rate_limit_conf)
    local identifier
    if rate_limit_conf.limit_by == "service" then
        identifier = (kong.router.get_service() or EMPTY).id
    elseif rate_limit_conf.limit_by == "ip" then
        if kong.request.get_header(rate_limit_conf.ip_header_name) ~= nil then
            identifier = iputils.get_client_ip(kong.request.get_header(rate_limit_conf.ip_header_name))
        end
    elseif rate_limit_conf.limit_by == "ip_deviceid" then
        local deviceid = "nodevice"
        local ip = "noip"

        local cookies = kong.request.get_header("cookie")
        if cookies ~= nil then
            deviceid = get_cookie(cookies, DEVICEID_WEB_COOKIE)
            if deviceid == nil then
                deviceid = get_cookie(cookies, DEVICEID_APP_COOKIE)
            end
        end

        if deviceid == nil then
            deviceid = "nodevice"
        end

        if kong.request.get_header(rate_limit_conf.ip_header_name) ~= nil then
            ip = iputils.get_client_ip(kong.request.get_header(rate_limit_conf.ip_header_name))
        end

        identifier = deviceid .. ":" .. ip
    elseif rate_limit_conf.limit_by == "header" then
        identifier = iputils.get_client_ip(kong.request.get_header(rate_limit_conf.header_name))
    elseif rate_limit_conf.limit_by == "consumer" then
        identifier = kong.request.get_header("X-Consumer-Username")
    elseif rate_limit_conf.limit_by == "cookie" then
        local cookies = kong.request.get_header("cookie")
        if cookies ~= nil then
            identifier = get_cookie(cookies, rate_limit_conf.cookie_name)
        end
    end

    if not identifier then
        return nil, "No rate-limiting identifier found in request"
    end

    return rate_limit_conf.rate_limiter_name .. ':' .. identifier
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

-- This function checks if auth logic is valid or not,
-- based on which should this rate limiter run
-- If auth is not valid, then this rate limiter should not be used
-- disable_on_auth    |    auth_cookie found and is not nil   => auth_check(return value)
-- FALSE              |    ANY                                => TRUE
-- TRUE               |    TRUE                               => FALSE
-- TRUE               |    FALSE                              => TRUE
local function auth_check(conf)
    if not conf.disable_on_auth then
        kong.log.info("Disable on auth is false.")
        return true
    end

    if conf.auth_type == 'cookie' then
        local cookies = kong.request.get_header("cookie")
        if cookies ~= nil then
            kong.log.info("Cookie result", get_cookie(cookies, conf.auth_cookie))
            local auth_valid = get_cookie(cookies, conf.auth_cookie) ~= nil
            kong.log.info("disable on auth was true. Auth validity - ", auth_valid)
            return not auth_valid
        else
            kong.log.info("No cookies found, disable on auth was true and auth is invalid")
            return true
        end

    else
        kong.log.err('Invalid auth type, ', conf.auth_type, '. disable on auth was true and auth is invalid')
        return true
    end
end

local function check_ratelimiter_applied(rate_limit_conf)
    if httputils.check_http_method(rate_limit_conf) == false then
        return false
    end

    if auth_check(rate_limit_conf) == false then
        return false
    end

    return true
end

local function check_ratelimit_reached(conf, rate_limit_conf, current_timestamp)
    -- Consumer is identified by ip address or authenticated_credential id
    local identifier, err = get_identifier(rate_limit_conf)

    if err then
        kong.log.err(err)
        return rate_limit_conf.block_access_on_error
    end

    -- Load current metric for configured period
    local limits = {
        second = rate_limit_conf.second,
        minute = rate_limit_conf.minute,
        hour = rate_limit_conf.hour,
        day = rate_limit_conf.day
    }

    local usage, stop, err = get_usage(conf, identifier, current_timestamp, limits)

    if err or not usage then
        kong.log.err("failed to get usage: ", tostring(err))
        return rate_limit_conf.block_access_on_error
    end

    metrics.increment_requests(
        kong.router.get_route()['name'],
        kong.router.get_service()['name'],
        identifier
    )

    if auth_check(rate_limit_conf) then
        -- Adding headers
        local reset
        local headers = {}
        headers["iden"] = identifier
        if rate_limit_conf.verbose_client_headers then
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

            headers['X-' .. rate_limit_conf.rate_limiter_name .. '-' .. X_RATELIMIT_LIMIT[k]] = current_limit
            headers['X-' .. rate_limit_conf.rate_limiter_name .. '-' .. X_RATELIMIT_REMAINING[k]] = current_remaining
          end

          headers['X-' .. rate_limit_conf.rate_limiter_name .. '-' .. RATELIMIT_LIMIT] = limit
          headers['X-' .. rate_limit_conf.rate_limiter_name .. '-' .. RATELIMIT_REMAINING] = remaining
          headers['X-' .. rate_limit_conf.rate_limiter_name .. '-' .. RATELIMIT_RESET] = reset
        end

        -- If get_usage succeeded and limit has been crossed
        if usage and stop then
            headers = headers or {}

            metrics.increment_requests_ratelimit_reached(
                rate_limit_conf.rate_limiter_name,
                rate_limit_conf.limit_by,
                kong.router.get_route()['name'],
                kong.router.get_service()['name'],
                identifier
            )
            kong.log.warn("Rate limit exceeded for identifier -", identifier)
            if rate_limit_conf.shadow_mode_enabled then
                if rate_limit_conf.shadow_mode_include_response_header then
                    headers[rate_limit_conf.shadow_mode_response_header_name] = true
                end
                if rate_limit_conf.shadow_mode_verbose_logging then
                    kong.log.warn("Rate limit exceeded for identifier ", identifier)
                end
                kong.response.set_headers(headers)
                return false
            else
                kong.log.err("API rate limit exceeded")
                headers['X-' .. rate_limit_conf.rate_limiter_name .. '-' .. RETRY_AFTER] = reset
                kong.response.set_headers(headers)
                return true
            end
        end

        kong.response.set_headers(headers)

    end

    return false
end

function RateLimitingHandler:init_worker(conf)
    metrics.init()
end

function protectedAccess(conf)
    local current_timestamp = time() * 1000

    -- Check if the IP is blacklisted
    -- if iputils.check_is_ip_blacklisted(conf) then
    --     return kong.response.exit(403, { error = { message = "IP is blacklisted" }})
    -- end

    -- Check if the IP is whitelisted
    -- if iputils.check_is_ip_whitelisted(conf) then
    --     headers = {}
    --     headers[WHITELISTED_IP_HEADER] = true
    --     kong.response.set_headers(headers)
    --     return
    -- end

    -- Add a header for which rate limiters are applied in priority
    if conf.rate_limiters_applied_header then
        local rate_limiters_applied = ""
        for key, rate_limiter in ipairs(conf.rate_limiters)
        do
            if check_ratelimiter_applied(rate_limiter) then
                rate_limiters_applied = rate_limiters_applied .. rate_limiter.rate_limiter_name .. ","
            end
        end

        local headers = {}
        headers[RATELIMITERS_APPLIED] = rate_limiters_applied
        kong.response.set_headers(headers)
    end

    -- Check rate limits and stop on the first rate limiter that fails
    for key, rate_limiter in ipairs(conf.rate_limiters)
    do
        local limit_reached = check_ratelimit_reached(conf, rate_limiter, current_timestamp)
        if limit_reached then
            return kong.response.exit(429, { error = { message = conf.error_message .. rate_limiter.rate_limiter_name }})
        end
    end

    -- Update limits for rate limiter
    kong.ctx.plugin.timer = function()
        for key, rate_limiter in ipairs(conf.rate_limiters)
        do
            local limits = {
                second = rate_limiter.second,
                minute = rate_limiter.minute,
                hour = rate_limiter.hour,
                day = rate_limiter.day
            }

            local limits_per_consumer
            if rate_limiter.limit_by == "consumer" then
                limits_per_consumer = cjson.decode(rate_limiter.limit_by_consumer_config)[kong.request.get_header("X-Consumer-Username")]
                if limits_per_consumer ~= nil then
                    limits = limits_per_consumer
                end
            end

            local identifier, err = get_identifier(rate_limiter)
            if err then
                kong.log.err(err)
            end

            local ok, err = timer_at(0, increment, conf, limits, identifier, current_timestamp, 1)
            if not ok then
                kong.log.err("failed to create timer: ", err)
            end
        end

    end
end

function RateLimitingHandler:access(conf)
    -- return protectedAccess(conf)

    local status, retval = pcall(protectedAccess, conf)
    if status then
        return retval
    else
        kong.log.err("Failed in executing access function for rate limiter", retval)
    end
end

function RateLimitingHandler:log(_)
    if kong.ctx.plugin.timer then
        kong.ctx.plugin.timer()
    end
end

return RateLimitingHandler
