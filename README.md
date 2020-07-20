<!--
 * @Author: your name
 * @Date: 2020-06-16 15:10:48
 * @LastEditTime: 2020-07-15 18:06:50
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