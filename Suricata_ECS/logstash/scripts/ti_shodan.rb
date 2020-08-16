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
    rescue Exception => e
        event.cancel
        return []
    end

    if not ipaddr_src.private?() then
        ioc = src_ip
    elsif not ipaddr_dst.private?() then
        ioc = dst_ip
    else
        return [event]
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
                event.set("[enrichment][services]", data["services"])
                event.set("[enrichment][vulns]", data["vulns"])
                event.set("[enrichment][ports]", data["ports"])
                event.set("[enrichment][hostnames]", data["hostnames"])
                event.set("[enrichment][domains]", data["domains"])
                event.set("[enrichment][details]", data["details"])
            end
        end
    end

    return [event]
end