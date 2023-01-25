local typedefs = require "kong.db.schema.typedefs"
local ORDERED_PERIODS = { "second", "minute", "hour", "day" }
local cjson = require "cjson"

local function validate_periods_order(config)
    for i, lower_period in ipairs(ORDERED_PERIODS) do
        local v1 = config[lower_period]
        if type(v1) == "number" then
            for j = i + 1, #ORDERED_PERIODS do
                local upper_period = ORDERED_PERIODS[j]
                local v2 = config[upper_period]
                if type(v2) == "number" and v2 < v1 then
                    return nil, string.format(
                        "The limit for %s(%.1f) cannot be lower than the limit for %s(%.1f)",
                        upper_period,
                        v2,
                        lower_period,
                        v1
                    )
                end
            end
        end
    end

    return true
end

local function validate_limits_per_consumer_config(config)
    return pcall(cjson.decode, config)
end

return {
    name = "quizizz-scalable-rate-limiter",
    fields = {
        { protocols = typedefs.protocols_http },
        {
            config = {
                type = "record",
                fields = {
                    {
                        rate_limiters = {
                            type = "array",
                            elements = {
                                type = "record",
                                fields = {
                                    {
                                        rate_limiter_name = {
                                            type = "string",
                                            required = true
                                        }
                                    },
                                    {
                                        second = {
                                            type = "number",
                                            gt = 0,
                                            required = false,
                                        },
                                    },
                                    {
                                        minute = {
                                            type = "number",
                                            gt = 0,
                                            required = false,
                                        },
                                    },
                                    {
                                        hour = {
                                            type = "number",
                                            gt = 0,
                                            required = false,
                                        },
                                    },
                                    {
                                        day = {
                                            type = "number",
                                            gt = 0,
                                            required = false,
                                        },
                                    },
                                    {
                                        limit_by = {
                                            type = "string",
                                            default = "service",
                                            one_of = { "service", "header", "consumer", "cookie" },
                                            required = false,
                                        },
                                    },
                                    {
                                        header_name = typedefs.header_name,
                                    },
                                    {
                                        cookie_name = {
                                            type = "string",
                                            required = false,
                                            required = false,
                                        },
                                    },
                                    {
                                        disable_on_auth = {
                                            type = "boolean",
                                            required = false,
                                            default = false,
                                            required = false,
                                        }
                                    },
                                    {
                                        auth_type = {
                                            type = "string",
                                            default = "cookie",
                                            one_of = { "cookie" },
                                            required = false,
                                        }
                                    },
                                    {
                                        auth_cookie = {
                                            type = "string",
                                            required = false,
                                        }
                                    },
                                    {
                                        shadow_mode_enabled = {
                                            type = "boolean",
                                            required = false,
                                            default = true,
                                        }
                                    },
                                    {
                                        shadow_mode_verbose_logging = {
                                            type = "boolean",
                                            required = false,
                                            default = true,
                                        }
                                    },
                                    {
                                        shadow_mode_include_response_header = {
                                            type = "boolean",
                                            required = false,
                                            default = true,
                                        }
                                    },
                                    {
                                        shadow_mode_response_header_name = {
                                            type = "string",
                                            required = false,
                                            default = "RateLimit-Exceeded",
                                        }
                                    },
                                    {
                                        block_access_on_error = {
                                            type = "boolean",
                                            required = false,
                                            default = true
                                        }
                                    }
                                },
                                custom_validator = validate_periods_order,
                            }
                        }
                    },
                    {
                        policy = {
                            type = "string",
                            default = "redis",
                            len_min = 0,
                            one_of = {
                                "redis",
                                "batch-redis",
                            },
                        },
                    },
                    {
                        batch_size = {
                            type = "integer",
                            gt = 1,
                            default = 10,
                        },
                    },
                    {
                        error_message = {
                            type = "string",
                            default = "API rate limit exceeded",
                            len_min = 0,
                        },
                    },
                    {
                        redis_host = typedefs.host {
                            required = true
                        },
                    },
                    {
                        redis_password = {
                            type = "string",
                            required = false
                        },
                    },
                    {
                        redis_port = typedefs.port {
                            default = 6379,
                        },
                    },
                    {
                        redis_connect_timeout = typedefs.timeout {
                            default = 200,
                        },
                    },
                    {
                        redis_send_timeout = typedefs.timeout {
                            default = 100,
                        },
                    },
                    {
                        redis_read_timeout = typedefs.timeout {
                            default = 100,
                        },
                    },
                    {
                        redis_keepalive_timeout = typedefs.timeout {
                            default = 60000,
                        },
                    },
                    {
                        redis_max_connection_attempts = {
                            type = "integer",
                            gt = 0,
                            default = 2,
                        },
                    },
                    {
                        redis_max_redirection = {
                            type = "integer",
                            gt = 0,
                            default = 2,
                        },
                    },
                    {
                        redis_pool_size = {
                            type = "integer",
                            gt = 0,
                            default = 4,
                        },
                    },
                    {
                        redis_backlog = {
                            type = "integer",
                            default = 1,
                        },
                    },
                    {
                        hide_client_headers = {
                            type = "boolean",
                            required = true,
                            default = false,
                        },
                    },
                    {
                        limit_by_consumer_config = {
                            type = "string",
                            required = false,
                            custom_validator = validate_limits_per_consumer_config
                        }
                    },
                },
            },
        },
    },
    entity_checks = {
        {
            conditional = {
                if_field = "config.policy",
                if_match = { eq = "batch-redis" },
                then_field = "config.batch_size",
                then_match = { required = true },
            },
        }
    },
}
