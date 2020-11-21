require "json"

def register(params)
    @pattern = /(?:\\n)?\w+ \d+ \d+:\d+:\d+ logstash NORMALIZED\[-\]: /
end

def filter(event)
    event_id = []
    rule_id = []
    rule_name = []
    event_log = event.get('[related][event][log]')

    atomic_rules = event_log.split(@pattern)[1 .. -1]
    for atomic in atomic_rules do
        e_id = JSON.parse(atomic)['event']['id']
        r_id = JSON.parse(atomic)['rule']['id']
        r_name = JSON.parse(atomic)['rule']['name']

        event_id.push(e_id)
        rule_id.push(r_id)
        rule_name.push(r_name)
    end
    event.set('[related][event][id]', event_id)
    event.set('[related][rule][id]', rule_id)
    event.set('[related][rule][name]', rule_name)
    event.remove('[related][event][log]')

    return [event]
end