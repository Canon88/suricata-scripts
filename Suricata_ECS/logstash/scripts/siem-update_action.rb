require "redis"


def register(params)
    begin
        @siem_action_db = Redis.new(host:params["host"], port:params["port"], password:params["password"], db:params["siem_action_db"])
    rescue
        return
    end
end


def filter(event)
    rule_id = event.get("[rule][id]")

    if @siem_action_db.exists?(rule_id) then
        event.set("[event][action]", "block")
    end

    return [event]
end