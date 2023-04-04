local kong = kong
local utils = require "kong.plugins.quizizz-scalable-rate-limiter.utils"
local pairs = pairs

local function check_http_method(conf)
    if conf.methods == "" then
        return true
    end

    if conf.methods == nil then
        return true
    end

    local allowed_http_methods = utils.string_to_array(conf.methods)
    local current_method = kong.request.get_method()

    for i, method in ipairs(allowed_http_methods) do
        if method == current_method then
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
    check_http_method = check_http_method,
    remove_last_ip = remove_last_ip
}
