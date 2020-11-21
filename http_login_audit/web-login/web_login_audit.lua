--[[
@Author: Canon
@Date: 2020-07-27 15:20:00
@LastEditTime: 2020-07-28 16:21:00
@LastEditors: Canon
@Description: Web Login Audit
@Version: 0.2
--]]

json = require "cjson.safe"
md5 = require "md5"

-- log_info
success_code = 0
app_type = "web"
event_type = "lua"
event_name = "login_audit"
name = "web_login_audit_demo.json"

-- read base config files
config_files = '/etc/suricata/lua-output/config/config_web_login.json'
template_mapping = '/etc/suricata/lua-output/config/template_web_login.json'

-- Password record
log_password = false

-- defind functioin
function md5Encode(args)
    m = md5.new()
    m:update(args)
    return md5.tohex(m:finish())
end

function urlDecode(args)
    s = string.gsub(args, "%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end)
    return s
end

function string.split(s, p)
    rt = {}
    string.gsub(s, '[^'..p..']+', function(w) table.insert(rt, w) end )
    return rt
end

function string.trim(s)
    return (string.gsub(s, "^%s*(.-)%s*$", "%1"))
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

function in_array(b, list)
    if not list then
        return false
    end 
    if list then
        for k, v in ipairs(list) do
            if v == b then
                return true
            end
        end
    end
end

function readJson(file)
    local file = io.open(file, 'r')
    local data = file:read('*a');
    file:close()
    return data
end

-- default function
function init (args)
    local needs = {}
    needs["protocol"] = "http"
    return needs
end

function setup (args)
    filename = SCLogPath() .. "/" .. name
    file = assert(io.open(filename, "a"))
    SCLogInfo("web_login_audit filename: " .. filename)

    config = json.decode(readJson(config_files))
    mapping = json.decode(readJson(template_mapping))

    -- core_mapping
    core_mapping_table = mapping['http_core_mapping']

    -- common_mapping
    common_mapping_table = mapping['http_common_mapping']
end

function log(args)
    -- init tables
    http_table = {
        request = {},
        response = {}
    }
    ti = {
        is_verify = false
    }

    -- hostname start
    http_hostname = HttpGetRequestHost()
    if http_hostname == nil then
        return
    end

    if not string.match(http_hostname, "romwe") then
        return
    end
    http_table["hostname"] = http_hostname
    -- hostname end
    
    -- url start
    http_url = HttpGetRequestUriNormalized()
    if not http_url then
        return
    end
    -- get url_path
    http_url_path = string.split(http_url, "?")[1]

    if ( next(config["url"]) ~= nil ) and ( not in_array(http_url_path, config["url"]) ) then
        return
    end
    http_table["url"] = http_url
    http_table["url_path"] = http_url_path
    -- url end

    -- method start
    rl = HttpGetRequestLine()
    if rl then
        http_method = string.match(rl, "%w+")
        if ( next(config["method"]) ~= nil ) and ( not in_array(http_method, config["method"]) ) then
            return
        end
        http_table["method"] = http_method
    end
    -- method end

    -- status_code & protocol
    rsl = HttpGetResponseLine()
    if rsl then
        status_code = string.match(rsl, "%s(%d+)%s")
        http_table["status"] = tonumber(status_code)

        http_protocol = string.match(rsl, "(.-)%s")
        http_table["protocol"] = http_protocol
    end

    -- get cookie
    cookie = HttpGetRequestHeader("Cookie")
    if cookie then
        http_table["cookie"] = cookie
    end

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
            else
                return
            end

            -- Add tags: is_verify by Canon 2020.07.01
            if res['challenge'] then
                is_verify = true
            end
            ti["is_verify"] = is_verify
        end
    end

    -- RequestHeaders
    rh = HttpGetRequestHeaders()
    if rh then
        for k, v in pairs(rh) do
            key = string.lower(k)

            core_var = core_mapping_table[key]
            if core_var then
                http_table[core_var] = v
            end
    
            common_var = common_mapping_table[key]
            if common_var then
                http_table["request"][common_var] = v
            end
        end
    end

    -- ResponseHeaders
    rsh = HttpGetResponseHeaders()
    if rsh then
        for k, v in pairs(rsh) do
            key = string.lower(k)

            core_var = core_mapping_table[key]
            if core_var then
                http_table[core_var] = v
            end
    
            common_var = common_mapping_table[key]
            if common_var then
                http_table["response"][common_var] = v
            end
        end
    end

    -- timestring = SCPacketTimeString() 2019-09-10T06:08:35.582449+0000
    sec, usec = SCPacketTimestamp()
    timestring = os.date("!%Y-%m-%dT%T", sec) .. '.' .. usec .. '+0000'
    
    -- flow_info
    ip_version, src_ip, dst_ip, protocol, src_port, dst_port = SCFlowTuple()

    -- flow_id
    id = SCFlowId()
    flow_id = string.format("%.0f", id)

    -- alerts
    has_alerts = SCFlowHasAlerts()

    -- true_client_ip
    if http_table["true_client_ip"] then
        http_table["proxy_ip"] = src_ip
        src_ip = http_table["true_client_ip"]
    end

    http_table["request"]["content_length"] = tonumber(http_table["request"]["content_length"])
    http_table["response"]["content_length"] = tonumber(http_table["response"]["content_length"])

    -- session_id
    session_id = md5Encode(src_ip .. http_hostname)

    -- table
    raw_data = {
        timestamp = timestring,
        flow_id = flow_id,
        session_id = session_id,
        src_ip = src_ip,
        src_port = src_port,
        proto = "TCP",
        dest_ip = dst_ip,
        dest_port = dst_port,
        event_name = event_name,
        event_type = event_type,
        app_type = app_type,
        http = http_table,
        ti = ti,
        alerted = has_alerts
    }

    -- json encode
    data = json.encode(raw_data)

    file:write(data .. "\n")
    file:flush()
end

function deinit (args)
    SCLogInfo("web_login_audit transactions logged.");
    file:close(file)
end