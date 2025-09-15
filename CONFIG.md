# 配置文件说明

## 配置文件位置
配置文件保存在：`%USERPROFILE%\CampusNetAuth\config.json`

## 配置文件格式

```json
{
  "account": "your_username",
  "password": "your_password",
  "check_url": "http://10.10.102.50:801/eportal/portal/online_list",
  "login_url": "http://10.10.102.50:801/eportal/portal/login?callback=dr1005&login_method=1&user_account=%2C0%2C{account}%40unicom&user_password={password}&wlan_user_ip={wlan_user_ip}&wlan_user_ipv6={wlan_user_ipv6}&wlan_user_mac=000000000000&wlan_ac_ip=&wlan_ac_name=&jsVersion=4.1.3&terminal_type=1",
  "auto_start": true,
  "check_interval": 30
}
```

## 参数说明

### account (字符串)
- 校园网登录账号
- 必填项

### password (字符串)
- 校园网登录密码
- 必填项

### check_url (字符串)
- 用于检测网络连接状态的URL
- 默认值：`http://10.10.102.50:801/eportal/portal/online_list`
- 返回格式应为：`jsonpReturn({"result":0/1,"msg":"..."})`

### login_url (字符串模板)
- 认证登录的URL模板
- 支持以下变量替换：
  - `{account}`: 账号（URL编码后）
  - `{password}`: 密码（URL编码后）
  - `{wlan_user_ip}`: 本机IPv4地址
  - `{wlan_user_ipv6}`: 本机IPv6地址（URL编码后）

### auto_start (布尔值)
- 是否开机自启动
- 默认值：`true`

### check_interval (数字)
- 网络状态检查间隔，单位：秒
- 默认值：`30`
- 范围：10-300秒

## IPv6地址格式化

程序会自动将IPv6地址格式化为校园网认证所需的格式：

输入：`2001:da8:a005:31a::4:21ee`
输出：`2001%3A0da8%3Aa005%3A031a%3A0000%3A0000%3A0004%3A21ee`

格式化规则：
1. 补齐每个段为4位十六进制数
2. 进行URL编码
