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

return {
    check_http_method = check_http_method
}
