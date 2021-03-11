require "json"
require "redis"
require "ipaddr"

def register(params)
    @expire = params["expire"]
    @alert = params["alert_prefix"]
    @alarm = params["alarm_prefix"]
    @spider_key = params["spider_key"]

    # connect to redis
    @ti_redis = Redis.new(host:params["host"], port:params["port"], password:params["password"], db:params["ti_db"])
    @spider_redis = Redis.new(host:params["host"], port:params["port"], password:params["password"], db:params["spider_db"])
end

def filter(event)
    src_ip = event.get("[source][ip]")
    dst_ip = event.get("[destination][ip]")

    begin
        ipaddr_src = IPAddr.new src_ip
        ipaddr_dst = IPAddr.new dst_ip

        # Check IP Private
        if not ipaddr_src.private?() then
            ioc = src_ip
        elsif not ipaddr_dst.private?() then
            ioc = dst_ip
        else
            return [event]
        end

    rescue Exception => e
        results_file = File.new("~/siem-ti_shodan_debug.txt", "a+")
        results_file.syswrite(e.to_s + ": " + event.to_s + "\n")
        event.cancel
        return []
    end

    if event.get("[event][kind]") == "alert" then
        alert_ioc = @alert + ioc
        if not @ti_redis.exists?(alert_ioc) then
            @ti_redis.setex(alert_ioc, @expire, true)
            @spider_redis.lpush(@spider_key, ioc)
        end
    end

    if event.get("[event][kind]") == "alarm" then
        raw_data = @ti_redis.get(@alarm + ioc)
        if raw_data then
            data = JSON.parse(raw_data)
            if data then
                event.set("[threat][hunting][services]", data["services"])
                event.set("[threat][hunting][vulns]", data["vulns"])
                event.set("[threat][hunting][ports]", data["ports"])
                event.set("[threat][hunting][hostnames]", data["hostnames"])
                event.set("[threat][hunting][domains]", data["domains"])
                if data["details"] then
                    details = data["details"].to_json
                    event.set("[threat][hunting][details]", details)
                end
            end
        end
    end

    return [event]
end