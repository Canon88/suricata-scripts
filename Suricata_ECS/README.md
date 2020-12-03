<!--
 * @Author: your name
 * @Date: 2020-08-06 15:59:11
 * @LastEditTime: 2020-12-03 14:31:34
 * @LastEditors: Please set LastEditors
 * @Description: In User Settings Edit
 * @FilePath: /Code/Users/canon/Documents/github/suricata-scripts/Suricata_ECS/logstash/conf.d/from_suricata_to_siem/README.md
--> 

#### workflow
Suricata -> Filebeat -> Logstash -> Elastic

#### 利用Ruby进行功能扩展
- add_direction.rb 为告警添加方向，根据IP地址以及规则同时进行判断，新增ECS字段如下；
```json
{
    "network": {
        "direction": "outbound",
        "zone": "internal"
    }
}
```
- siem-filter_ip.rb 通过调用Redis来获取需要过滤的IP地址；
- siem-filter_sid.rb 通过调用Redis来获取需要过滤的规则ID；
- normalized_http_headers.rb 针对Suricata HTTP header进行标准化；
- siem-ti_shodan.rb 通过Shodan进行告警IP的丰富化；
```json
{
    "enrichment": {
        "vulns": [],
        "domains": [
            "hwclouds-dns.com"
        ],
        "details": {
            "udp": [],
            "tcp": [
                {
                    "http-simple-new": 9200
                },
                {
                    "auto": 8848
                },
                {
                    "https": 443
                },
                {
                    "http": 80
                }
            ]
        },
        "hostnames": [
            "ecs-119-3-116-192.compute.hwclouds-dns.com"
        ],
        "services": [
            "http",
            "http-simple-new",
            "https",
            "auto"
        ],
        "ports": [
            9200,
            8848,
            443,
            80
        ]
    }
}
```

- siem-filter_sid.rb 通过调用Redis来获取需要过滤 d规则ID；
- siem-filter_signature.rb 通过调用Redis来获取需要过滤的规则；
- siem-update_action.rb 通过Redis进行SIEM block规则的统一维护；
- ti_tags.rb 对接本地威胁情报；
- siem-add_request_id.rb 为Imperva与Suricata增加统一关联ID；
- siem-filter_sensor.rb 只有白名单中的 host.name 才会推送到SIEM上. 避免短时间内新增的NTA 或者 WAF没有足够的时间做规则收敛,导致SIEM侧的API自动推送造成误封堵的现象.



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

## 从filebeat更新ECS模板至ES
参考：**[Load the Elasticsearch index template](https://www.elastic.co/guide/en/beats/filebeat/7.10/filebeat-template.html#load-template-manually)**
```bash
# 直接从filebeat导入到Elastic
$ filebeat setup --index-management -E output.logstash.enabled=false -E output.elasticsearch.protocol=https -E output.elasticsearch.username=elastic -E output.elasticsearch.password=HelloWorld -E output.elasticsearch.ssl.certificate_authorities=['/etc/filebeat/certs/ca/ca.crt'] -E 'output.elasticsearch.hosts=["127.0.0.1:9200"]'

Overwriting ILM policy is disabled. Set `setup.ilm.overwrite: true` for enabling.

Index setup finished.

# filebeat导出至本地，再上传到可以直接连接Elastic的机器上导入。
$ filebeat export template > filebeat.template.json
$ curl -XPUT -H 'Content-Type: application/json' http://localhost:9200/_template/filebeat-7.10.0 -d@filebeat.template.json
```