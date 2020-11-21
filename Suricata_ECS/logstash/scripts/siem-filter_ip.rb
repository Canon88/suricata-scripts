require "redis"


def register(params)
    begin
        @cdn_db = Redis.new(host:params["host"], port:params["port"], password:params["password"], db:params["cdn_db"])
        @scan_db = Redis.new(host:params["host"], port:params["port"], password:params["password"], db:params["scan_db"])
    rescue
        return
    end
end


def filter(event)
    src_ip = event.get("[source][ip]")
    dst_ip = event.get("[destination][ip]")

    if @cdn_db.exists?(src_ip) || @cdn_db.exists?(dst_ip) || @scan_db.exists?(src_ip) || @scan_db.exists?(dst_ip) then
        event.cancel
        return []
    end

    return [event]
end