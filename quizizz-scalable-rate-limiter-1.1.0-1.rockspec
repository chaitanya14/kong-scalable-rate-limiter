package = "quizizz-scalable-rate-limiter"

version = "1.1.0-1"

supported_platforms = {"linux", "macosx"}

source = {
    url = "git@github.com:quizizz/kong-scalable-rate-limiter.git",
    tag = "v1.1.0"
}

description = {
    summary = "Scalable Rate Limiter plugin for Kong API Gateway"
}

dependencies = {

}

build = {
    type = "builtin",
    modules = {
        ["kong.plugins.quizizz-scalable-rate-limiter.handler"] = "kong/plugins/quizizz-scalable-rate-limiter/handler.lua",
        ["kong.plugins.quizizz-scalable-rate-limiter.schema"] = "kong/plugins/quizizz-scalable-rate-limiter/schema.lua",
        ["kong.plugins.quizizz-scalable-rate-limiter.expiration"] = "kong/plugins/quizizz-scalable-rate-limiter/expiration.lua",
        ["kong.plugins.quizizz-scalable-rate-limiter.policies"] = "kong/plugins/quizizz-scalable-rate-limiter/policies/init.lua",
        ["kong.plugins.quizizz-scalable-rate-limiter.policies.connection"] = "kong/plugins/quizizz-scalable-rate-limiter/policies/connection.lua",

        ["resty.rediscluster"] = "kong/plugins/quizizz-scalable-rate-limiter/resty-redis-cluster/rediscluster.lua",
        ["resty.xmodem"] = "kong/plugins/quizizz-scalable-rate-limiter/resty-redis-cluster/xmodem.lua"
    }
}
