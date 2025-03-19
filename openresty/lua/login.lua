-- my_module.lua
local jwt = require "resty.jwt"
local cjson = require "cjson"

local _M = {}

-- Helper function to load config dynamically
local load_config = function()
    package.loaded["config"] = nil
    return require "config"
end

-- Function to validate provided credentials
local function is_valid_credential(provided_key, provided_secret, credentials)
    for _, cred in ipairs(credentials) do
        if cred.key == provided_key and cred.secret == provided_secret then
            return true
        end
    end
    return false
end

-- Public function to generate a JWT token
function _M.generate_token()
    -- Dynamically load config
    local config = load_config()

    -- Get key, secret, and user from headers
    local provided_key = ngx.req.get_headers()["X-API-Key"]
    local provided_secret = ngx.req.get_headers()["X-API-Secret"]
    local user = ngx.req.get_headers()["X-User"]

    -- Validate provided key and secret
    if not is_valid_credential(provided_key, provided_secret, config.credentials) then
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.say(cjson.encode({ error = "Unauthorized" }))
        return
    end

    -- Generate token if validation is successful
    local payload = {
        user = user,  -- Use dynamically passed user information
        exp = ngx.time() + 3600  -- Token expiration time
    }

    local token = jwt:sign(config.jwt_secret, {
        header = { typ = "JWT", alg = "HS256" },
        payload = payload
    })

    return token
end

return _M