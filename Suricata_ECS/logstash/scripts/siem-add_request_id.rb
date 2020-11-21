require "digest/md5"

def register(params)
    @src_ip = params["src_ip"]
    @dst_ip = params["dst_ip"]
    @hostname = params["hostname"]
    @url_path = params["url_path"]
    @method = params["method"]
    @timestamp = params["timestamp"]
end

def filter(event)
    src_ip = event.get(@src_ip)
    dst_ip = event.get(@dst_ip)
    hostname = event.get(@hostname)
    url_path = event.get(@url_path)
    method = event.get(@method)
    timestamp = event.get(@timestamp)
    timestamp = /\d+-\d+-\d+T\d+:\d+/.match(timestamp.to_s)[0]

    if src_ip && dst_ip && hostname && url_path && method && timestamp then
        data = src_ip + dst_ip + hostname + url_path + method + timestamp
        request_id = Digest::MD5.hexdigest(data)
        event.set("[http][request][id]", request_id)
    end

    return [event]
end