require "redis"
require "ipaddr"

def register(params)
    @expire = params["expire"]
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

    if not @ti_redis.exists?(ioc) then
        @ti_redis.setex(ioc, @expire, true)
        @spider_redis.lpush(@spider_key, ioc)
    end

    return [event]
end