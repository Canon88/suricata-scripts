# suricata-scripts

## http_login_audit.lua
- 1. 针对网站登录接口进行事件解析，生成对应的login_audit事件。
- 2. 针对登录网站的账户与密码进行威胁情报的判断，生成对应的tags: [account leak, password leak]。
- 3. 通过判断challenge字段，检查是否为绕过验证码登录的行为；