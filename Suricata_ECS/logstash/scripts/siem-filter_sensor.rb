def register(params)
    require "json"
    
    data  = File.read(params["file"])
    whitelist = JSON.parse(data)
    nta_shein = whitelist['nta']['http']['shein']
    nta_romwe = whitelist['nta']['http']['romwe']
    nta_dns = whitelist['nta']['dns']
    @sensor = nta_shein + nta_romwe + nta_dns
end

def filter(event)
    if @sensor.include?(event.get('[host][name]')) then
        return [event]
    else
        event.cancel
        return []
    end
end