<!--
 * @Author: your name
 * @Date: 2020-06-16 15:10:48
 * @LastEditTime: 2020-07-20 17:44:49
 * @LastEditors: Please set LastEditors
 * @Description: In User Settings Edit
 * @FilePath: /Code/Users/canon/Documents/github/suricata-scripts/README.md
--> 
# suricata-scripts

## http_login_audit
- 1. 针对网站登录接口进行事件解析，生成对应的login_audit事件。
- 2. 针对登录网站的账户与密码进行威胁情报的判断，生成对应的tags: [account leak, password leak]。
- 3. 通过判断challenge字段，检查是否为绕过验证码登录的行为；

## http_audit
- 1. 解决通过**alert**编写**audit**规则，不够定制化的需求
- 2. **config.json**, 支持黑白名单设置
- 3. **template.json**, 指定需要审计的内容
**Sample:**
```json
{
    "alerted": false,
    "src_port": 48838,
    "session_id": "c5ca685bbb69032c7284e344ae3122e9",
    "proto": "TCP",
    "flow_id": "162347013217236",
    "timestamp": "2020-07-20T08:56:10.64623+0000",
    "event_type": "lua",
    "src_ip": "189.171.21.136",
    "dest_port": 8001,
    "http": {
        "proxy-ip": "192.168.1.1",
        "url_path": "/xxxxxxx",
        "protocol": "HTTP/1.1",
        "hostname": "canon88.github.io",
        "true-client-ip": "189.171.21.136",
        "status": 200,
        "method": "POST",
        "response": {
            "server": "nginx",
            "transfer-encoding": "chunked",
            "connection": "keep-alive",
            "cache-control": "no-cache, max-age=0, no-store",
            "pragma": "no-cache",
            "date": "Mon, 20 Jul 2020 08:56:10 GMT",
            "content-encoding": "gzip",
            "vary": "Accept-Encoding",
            "content-type": "application/json;charset=UTF-8"
        },
        "xff": "189.171.21.136, 209.95.131.159, 72.249.195.175",
        "url": "xxxxxxx",
        "x-real-ip": "72.249.195.175",
        "request": {
            "content-type": "application/x-www-form-urlencoded",
            "content-length": 74,
            "accept-encoding": "gzip",
            "pragma": "no-cache",
            "x-forwarded-proto": "https",
            "via": "1.1 v1-akamaitech.net(ghost) (AkamaiGHost), 1.1 akamai.net(ghost) (AkamaiGHost)",
            "body": "this is a request body",
            "cache-control": "no-cache, max-age=0",
            "accept": "application/json"
        },
        "user-agent": "xxxxxxxxxx"
    },
    "event_name": "http",
    "dest_ip": "10.161.11.140",
    "app_type": "web"
}
```