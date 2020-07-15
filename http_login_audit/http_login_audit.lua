-- version: 0.1
-- author: Canon

json = require "cjson.safe"
md5 = require "md5"
redis = require "redis"

-- login api
m_login_url = "/user/login"
web_login_url = "/user/auth/login"

-- response_code
success_code = 0
verify_code = -405
-- event_name
event_name = "login_audit"
-- event_type
event_type = "lua"
-- app_type
app_type = "web"
-- logs_files
name = "web_login_audit.json"
-- protocol
proto = "TCP"
-- 威胁情报
ti_canon_prefix = "ti:canon:"

-- common_mapping
http_common_mapping =
    '{"accept":"accept","accept-charset":"accept_charset","accept-encoding":"accept_encoding","accept-language":"accept_language","accept-datetime":"accept_datetime","authorization":"authorization","cache-control":"cache_control","from":"from","max-forwards":"max_forwards","origin":"origin","pragma":"pragma","proxy-authorization":"proxy_authorization","via":"via","vary":"vary","x-requested-with":"x_requested_with","x-forwarded-proto":"x_forwarded_proto","accept-range":"accept_range","allow":"allow","connection":"connection","content-encoding":"content_encoding","content-language":"content_language","content-location":"content_location","content-md5":"content_md5","content-range":"content_range","date":"date","last-modified":"last_modified","location":"location","proxy-authenticate":"proxy_authenticate","referrer":"refer","retry-after":"retry_after","server":"server","transfer-encoding":"transfer_encoding","upgrade":"upgrade","www-authenticate":"www_authenticate","x-authenticated-user":"x_authenticated_user","user-agent":"user_agent"}'
common_mapping_table = json.decode(http_common_mapping)

-- request_mapping
http_request_mapping =
    '{"content-length":"request_content_length","content-type":"request_content_type","usercountry":"user_country","localcountry":"local_country","canvas":"canvas","webgl":"webgl","x-ftoken":"x-ftoken"}'
request_mapping_table = json.decode(http_request_mapping)

-- response_mapping
http_response_mapping =
    '{"content-length":"response_content_length","content-type":"response_content_type"}'
response_mapping_table = json.decode(http_response_mapping)

-- redis_config
host = "8.8.8.8"
port = 6379
password = "HelloWorld"
db = 9

-- defind functioin
function md5Encode(args)
    m = md5.new()
    m:update(args)
    return md5.tohex(m:finish())
end

function urlDecode(args)
    s = string.gsub(args, "%%(%x%x)",
                    function(h) return string.char(tonumber(h, 16)) end)
    return s
end

-- email=xxxx@gmail.com&password=yyyy
function formatBody(args)
    t = {}
    data = string.split(args, '&')
    for n, v in ipairs(data) do
        d = string.split(v, '=')
        t[d[1]] = d[2]
    end
    return t
end

function formatCookie(args)
    t = {}
    data = string.split(args, ";")
    for n, v in ipairs(data) do
        v = string.trim(v)
        d = string.split(v, "=")
        t[d[1]] = d[2]
    end
    return t
end

function string.split(s, p)
    local rt = {}
    string.gsub(s, '[^' .. p .. ']+', function(w) table.insert(rt, w) end)
    return rt
end

function string.trim(s) return (string.gsub(s, "^%s*(.-)%s*$", "%1")) end


-- default function
function init(args)
    local needs = {}
    needs["protocol"] = "http"
    return needs
end

function setup(args)
    filename = SCLogPath() .. name
    file = assert(io.open(filename, "a"))
    SCLogInfo("http_login_audit filename: " .. filename)
    http = 0

    -- Connect Redis Server
    SCLogInfo("Connect Redis Server...")
    client = redis.connect(host, port)
    client:auth(password)
    local response = client:ping()
    if response then SCLogInfo("Redis Server connection succeeded.") end
    client:select(db)
    SCLogInfo("Current database: " .. db)
end

function log(args)

    -- init tables
    http_table = {}

    -- ti tables
    ti = {tags = {}}

    -- log_password
    log_password = false

    -- log_verify_results
    is_verify = false

    http_hostname = HttpGetRequestHost()
    if not http_hostname then return end
    if not string.match(http_hostname, "canon88.github.io") then return end
    http_table["hostname"] = http_hostname

    http_url = HttpGetRequestUriNormalized()
    http_table["url"] = http_url
    http_table["url_path"] = http_url

    rl = HttpGetRequestLine()
    if rl then http_method = string.match(rl, "%w+") end
    if not http_method == "POST" then return end
    http_table["method"] = http_method

    if http_url == web_login_url or http_url == m_login_url then
        rsl = HttpGetResponseLine()
        if rsl then
            status_code = string.match(rsl, "%s(%d+)%s")
            http_table["status"] = tonumber(status_code)

            http_protocol = string.match(rsl, "(.-)%s")
            http_table["protocol"] = http_protocol
        end

        -- get cookie
        cookie = HttpGetRequestHeader("Cookie")
        if cookie then http_table["cookie"] = cookie end

        -- get set_cookie && member_id
        set_cookie = HttpGetResponseHeader("Set-Cookie")
        if set_cookie then
            http_table["set_cookie"] = set_cookie
            member_id = string.match(set_cookie, "memberId=(.-);")
            if member_id then
                http_table["member_id"] = tonumber(member_id)
            end
        end

        -- login_results
        a, o, e = HttpGetResponseBody()
        if a then
            for n, v in ipairs(a) do
                body = json.decode(v)
                if body then
                    results_code = tonumber(body["code"])
                    if results_code == success_code then
                        results = "success"
                    else
                        results = "failed"
                        http_table["results_msg"] = body["msg"]
                    end
                    http_table["results"] = results
                    http_table["results_code"] = results_code
                end
            end
        end

        -- email & password
        a, o, e = HttpGetRequestBody()
        if a then
            for n, v in ipairs(a) do
                res = formatBody(v)

                if res['email'] then
                    http_table["email"] = urlDecode(res['email'])

                    if res['password'] then
                        password = md5Encode(res['password'])
                        -- Account information leakage
                        black_ioc = client:get(
                                        ti_canon_prefix .. http_table["email"])
                        -- Password information leakage
                        if black_ioc then
                            ti["provider"] = "canon"
                            ti["producer"] = "NTA"
                            table.insert(ti["tags"], "account leak")

                            if black_ioc == password then
                                table.insert(ti["tags"], "password leak")
                                -- log login password default false
                                if log_password then
                                    http_table["password"] = password
                                end
                            end
                        end
                    end
                end

                if res['challenge'] then is_verify = true end
            end
        end

        -- RequestHeaders
        rh = HttpGetRequestHeaders()
        if rh then
            for k, v in pairs(rh) do
                key = string.lower(k)

                common_var = common_mapping_table[key]
                if common_var then http_table[common_var] = v end

                request_var = request_mapping_table[key]
                if request_var then http_table[request_var] = v end
            end
        end

        -- ResponseHeaders
        rsh = HttpGetResponseHeaders()
        if rsh then
            for k, v in pairs(rsh) do
                key = string.lower(k)

                common_var = common_mapping_table[key]
                if common_var then http_table[common_var] = v end

                response_var = response_mapping_table[key]
                if response_var then http_table[response_var] = v end
            end
        end

        -- timestring = SCPacketTimeString() 2019-09-10T06:08:35.582449+0000
        sec, usec = SCPacketTimestamp()
        timestring = os.date("!%Y-%m-%dT%T", sec) .. "." .. usec .. "+0000"

        ip_version, src_ip, dst_ip, protocol, src_port, dst_port = SCFlowTuple()

        -- flow_id
        id = SCFlowId()
        flow_id = string.format("%.0f", id)

        -- true_ip
        true_client_ip = HttpGetRequestHeader("True-Client-IP")
        if true_client_ip ~= nil then src_ip = true_client_ip end

        -- session_id
        session_id = md5Encode(src_ip .. http_hostname)

        -- table
        raw_data = {
            timestamp = timestring,
            flow_id = flow_id,
            session_id = session_id,
            src_ip = src_ip,
            src_port = src_port,
            proto = proto,
            dest_ip = dst_ip,
            dest_port = dst_port,
            event_name = event_name,
            event_type = event_type,
            app_type = app_type,
            http = http_table,
            ti = ti,
            is_verify = is_verify
        }

        -- json encode
        data = json.encode(raw_data)

        file:write(data .. "\n")
        file:flush()

        http = http + 1
    end

end

function deinit(args)
    SCLogInfo("http_login_audit transactions logged: " .. http);
    file:close(file)
end
