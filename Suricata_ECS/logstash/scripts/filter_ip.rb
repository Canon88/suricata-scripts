require "redis"

def register(params)
    @cdn_ip = Redis.new(host:params["host"], port:params["port"], password:params["password"], db:params["cdn_db"])
    @scan_ip = Redis.new(host:params["host"], port:params["port"], password:params["password"], db:params["scan_db"])
end

def filter(event)
    src_ip = event.get("[source][ip]")
    dst_ip = event.get("[destination][ip]")
    if @cdn_ip.exists?(src_ip) || @cdn_ip.exists?(dst_ip) || @scan_ip.exists?(src_ip) || @scan_ip.exists?(dst_ip) then
        event.cancel
        return []
    end
    return [event]
end