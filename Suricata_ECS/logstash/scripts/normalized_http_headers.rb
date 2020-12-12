def filter(event)
    request = {}
    response = {}

    request_headers = event.get("[suricata][eve][http][request_headers]")
    response_headers = event.get("[suricata][eve][http][response_headers]")

    if request_headers then
        request_headers.each do |headers|
            name = headers['name'].to_s.downcase
            value = headers['value']
            request[name] = value
        end
    end

    if response_headers then
        response_headers.each do |headers|
            name = headers['name'].to_s.downcase
            value = headers['value']
            response[name] = value
        end
    end

    event.remove("[suricata][eve][http][request_headers]")
    event.remove("[suricata][eve][http][response_headers]")
    event.set("[suricata][eve][http][request]", request)
    event.set("[suricata][eve][http][response]", response)
    return [event]
end