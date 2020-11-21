require "redis"

def register(params)
    @signature_id = Redis.new(host:params["host"], port:params["port"], password:params["password"], db:params["sid_db"])
end

def filter(event)
    sid = event.get("[rule][id]")
    if @signature_id.exists?(sid) then
        event.cancel
        return []
    end
    return [event]
end