local kong = kong
local ipmatcher = require("resty.ipmatcher")
local policies = require "kong.plugins.quizizz-scalable-rate-limiter.policies"
local pairs = pairs
local time = ngx.time

local WHITELISTED_IPS_SET_KEY = "whitelisted_ips"
local BLACKLISTED_IPS_SET_KEY = "blacklisted_ips"

local function check_ip_matches_cidr(cidrs, ip)
    local cidr_matcher = ipmatcher.new(cidrs)
    return cidr_matcher:match(ip)
end

local function check_is_ip_whitelisted(conf)
    local latency_current_timestamp = time()

    if kong.request.get_header('x-forwarded-for') == nil then
        return false
    end

    local cidrs = policies[conf.policy].get_whitelist_cidrs(conf, WHITELISTED_IPS_SET_KEY)

    local header = kong.request.get_header('x-forwarded-for')
    for i in string.gmatch(header, "[0-9.]+") do
        if check_ip_matches_cidr(cidrs, i) then
            return true
        end
    end
    return false
end

local function check_is_ip_blacklisted(conf)
    local latency_current_timestamp = time()

    if kong.request.get_header('x-forwarded-for') == nil then
        return false
    end

    local cidrs = policies[conf.policy].get_blacklist_cidrs(conf, BLACKLISTED_IPS_SET_KEY)

    local header = kong.request.get_header('x-forwarded-for')
    for i in string.gmatch(header, "[0-9.]+") do
        if check_ip_matches_cidr(cidrs, i) then
            return true
        end
    end
    return false
end

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

return {
    check_ip_matches_cidr = check_ip_matches_cidr,
    check_is_ip_whitelisted = check_is_ip_whitelisted,
    check_is_ip_blacklisted = check_is_ip_blacklisted,
    remove_last_ip = remove_last_ip
}
