<!--
 * @Author: your name
 * @Date: 2020-08-06 15:59:11
 * @LastEditTime: 2020-08-13 11:34:17
 * @LastEditors: Please set LastEditors
 * @Description: In User Settings Edit
 * @FilePath: /Code/Users/canon/Documents/github/suricata-scripts/Suricata_ECS/logstash/conf.d/from_suricata_to_siem/README.md
--> 

# Workflow
Suricata -> Filebeat -> Logstash -> Elastic

## 利用Ruby进行功能扩展
- add_direction.rb 为告警添加方向，根据IP地址以及规则同时进行判断，新增ECS字段如下；
```json
{
    "network": {
        "direction": "outbound",
        "zone": "internal"
    }
}
```
- filter_ip.rb 通过调用Redis来获取需要过滤的IP地址；
- filter_sid.rb 同上，Suricata SID过滤；
- normalized_http_headers.rb 针对Suricata HTTP header进行标准化；
- ti_shodan.rb 通过Shodan进行攻击IP的丰富化，这里需要配合爬虫；

## Logstash自带的UA插件不如Elastic的方便。所以这里需要手动添加pipeline，通过Elasic处理User-Agent. 
```bash
PUT _ingest/pipeline/nta-suricata-ecs
{
    "description": "Add Suricata EVE Information.",
    "processors": [
        {
        "user_agent": {
            "ignore_missing": true,
            "field": "user_agent.original"
        }
        }
    ]
}
```