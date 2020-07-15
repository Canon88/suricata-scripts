--[[
@Author: Canon
@Date: 2020-07-15 17:48:48
@LastEditTime: 2020-07-15 17:48:48
@LastEditors: Canon
@Description: HTTP Audit Script
@Version: 0.1
--]]

json = require "cjson.safe"
md5 = require "md5"

-- log_info
app_type = "web"
event_type = "lua"
event_name = "http"
name = "http_audit_demo.json"

-- read base config files
config_files = '/etc/suricata/lua-output/config/config.json'
template_mapping = '/etc/suricata/lua-output/config/tempplate.json'

-- defind function
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

function formatBody(args)
    t = {}
    data = string.split(args, '&')
    for n, v in ipairs(data) do
        d = string.split(v, '=')
        t[d[1]] = d[2]
    end
    return t
end

function readJson(file)
    local file = io.open(file, 'r')
    local data = file:read('*a');
    file:close()
    return data
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

-- default funtion
function init(args)
    local needs = {}
    needs["protocol"] = "http"
    return needs
end

function setup(args)
    filename = SCLogPath() .. "/" .. name
    file = assert(io.open(filename, "a"))
    SCLogInfo("http_audit filename: " .. filename)

    config = json.decode(readJson(config_files))
    mapping = json.decode(readJson(template_mapping))
    
    -- common_mapping
    common_mapping_table = mapping['http_common_mapping']
    
    -- request_mapping
    request_mapping_table = mapping['http_request_mapping']
    
    -- response_mapping
    response_mapping_table = mapping['http_response_mapping']
end

function log(args)
    -- init tables
    http_table = {
        request = {},
        response = {}
    }

    -- hostname start
    http_hostname = HttpGetRequestHost()
    if not http_hostname then
        return
    end

    if config["blacklist"]["hostname"] == "enable" then
        if in_array(http_hostname, config["hostname"]) then
            return
        end
    else
        if ( not in_array("any", config["hostname"]) ) and ( not in_array(http_hostname, config["hostname"]) ) then
            return
        end
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

    if config["blacklist"]["url"] == "enable" then
        if in_array(http_url_path, config["url"]) then
            return
        end
    else
        if ( not in_array("any", config["url"]) ) and not ( in_array(http_url_path, config["url"]) ) then
            return
        end
    end
    http_table["url"] = http_url
    http_table["url_path"] = http_url_path
    -- url end

    -- user_agent start
    http_ua = HttpGetRequestHeader("User-Agent")
    if http_ua then
        for _, ua in ipairs(config["ua"]) do
            if config["blacklist"]["ua"] == "enable" then
                if string.match(http_ua, ua) then
                    return
                end
            else
                if ( not in_array("any", config["ua"]) ) and ( not string.match(http_ua, ua) ) then
                    return
                end
            end
        end
    end
    http_table["user_agent"] = http_ua
    -- user_agent end

    -- method start
    rl = HttpGetRequestLine()
    if rl then
        http_method = string.match(rl, "%w+")
        if config["blacklist"]["method"] == "enable" then
            if in_array(http_method, config["method"]) then
                return
            end
        else
            if ( not in_array("any", config["method"]) ) and ( not in_array(http_method, config["method"]) ) then
                return
            end
        end
        http_table["method"] = http_method
    end
    -- method end

    rsl = HttpGetResponseLine()
    if rsl then
        status_code = string.match(rsl, "%s(%d+)%s")
        http_table["status"] = tonumber(status_code)

        http_protocol = string.match(rsl, "(.-)%s")
        http_table["protocol"] = http_protocol
    end

    cookie = HttpGetRequestHeader("Cookie")
    http_table["cookie"] = cookie

    set_cookie = HttpGetResponseHeader("Set-Cookie")
    http_table["set_cookie"] = set_cookie

    -- RequestHeaders
    rh = HttpGetRequestHeaders()
    if rh then
        for k, v in pairs(rh) do
            key = string.lower(k)

            common_var = common_mapping_table[key]
            if common_var then
                http_table["request"][common_var] = v
            end

            request_var = request_mapping_table[key]
            if request_var then
                http_table["request"][request_var] = v
            end
        end
    end

    -- ResponseHeaders
    rsh = HttpGetResponseHeaders()
    if rsh then
        for k, v in pairs(rsh) do
            key = string.lower(k)
    
            common_var = common_mapping_table[key]
            if common_var then
                http_table["response"][common_var] = v
            end
    
            response_var = response_mapping_table[key]
            if response_var then
                http_table["response"][response_var] = v
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
    true_client_ip = HttpGetRequestHeader("True-Client-IP")
    if true_client_ip then
        http_table["proxy_ip"] = src_ip
        http_table["true_client_ip"] = true_client_ip
        src_ip = true_client_ip
    end

    http_table["response"]["content_length"] = tonumber(http_table["response"]["content_length"])
    http_table["request"]["content_length"] = tonumber(http_table["request"]["content_length"])

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
        alerted = has_alerts
    }

    -- json encode
    data = json.encode(raw_data)

    -- write_data
    file:write(data .. "\n")
    file:flush()
end

function deinit (args)
    SCLogInfo("http_audit transactions logged.")
    file:close(file)
end