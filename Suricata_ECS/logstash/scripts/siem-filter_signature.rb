require "redis"

def register(params)
    @signature_db = Redis.new(host:params["host"], port:params["port"], password:params["password"], db:params["sig_db"])
end

def filter(event)
    rule_name = event.get("[rule][name]")
    if @signature_db.exists?(rule_name) then
        event.cancel
        return []
    end
    return [event]
end
