require "ipaddr"


def filter(event)
    src_ip = event.get("[source][ip]")
    dst_ip = event.get("[destination][ip]")
    if not src_ip or not dst_ip then
        event.cancel
        return []
    end
    ipaddr_src = IPAddr.new src_ip
    ipaddr_dst = IPAddr.new dst_ip

    # Sample: alert http $EXTERNAL_NET any -> $HOME_NET any
    rule = event.get("[rule][description]")
    src_direction = rule.split(" ")[2]
    dst_direction = rule.split(" ")[5]

    src_private = ipaddr_src.private?()
    dst_private = ipaddr_dst.private?()
    
    if ( src_private ) and ( src_direction == "$EXTERNAL_NET" ) then
        event.cancel
        return []
    end

    if ( dst_private ) and ( dst_direction == "$EXTERNAL_NET" ) then
        event.cancel
        return []
    end

    if src_private and dst_private then
        direction = "outbound"
        zone = "internal"
    elsif src_private and not dst_private then
        direction = "outbound"
        zone = "internal"
    elsif not src_private and dst_private then
        direction = "inbound"
        zone = "external"
    else
        direction = "inbound"
        zone = "external"
    end

    event.set("[network][direction]", direction)
    event.set("[network][zone]", zone)
    return [event]
end