require "json"

def register(params)
    @pattern = /(?:\\n)?\w+ \d+ \d+:\d+:\d+ logstash NORMALIZED\[-\]: /
end

def filter(event)
    event_id = []
    previous_output = event.get('previous_output')
    atomic_rules = previous_output.split(@pattern)[1 .. -1]
    for atomic in atomic_rules do
        id = JSON.parse(atomic)['event']['id']
        event_id.push(id)
    end
    event.set('[related][event][id]', event_id)

    return [event]
end