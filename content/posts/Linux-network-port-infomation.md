---
title: "Linux上使用netstat查看当前服务和监听端口"
date: 2018-10-23T14:35:11-05:00
draft: false
tags: ["Linux"]
---

netstat这个命令常用在网络监控方面。利用这个命令，可以查看当前系统监听的服务和已经建立的服务，以及相应的端口、协议等信息。

# Parameters

netstat参数虽然很多，但是常用的不多，主要是下面几个参数：

```bash
netstat -[atunlp]
```

- -a ：all，表示列出所有的连接，服务监听，Socket资料
- -t ：tcp，列出tcp协议的服务
- -u ：udp，列出udp协议的服务
- -n ：port number， 用端口号来显示
- -l ：listening，列出当前监听服务
- -p ：program，列出服务程序的PID

如果你需要深入了解，可以用man netstat查看netstat命令的详细说明。

# Example

在Terminal终端输入`netstat -atunlp`命令后，显示结果如下

```bash
root@ubuntu:~# netstat -atunlp
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.1.1:53            0.0.0.0:*               LISTEN      1536/dnsmasq    
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      6207/cupsd      
tcp        1      0 192.168.89.136:49384    91.189.94.25:80         CLOSE_WAIT  7384/ubuntu-geoip-p
tcp        0      0 192.168.89.136:55930    192.168.89.139:80       ESTABLISHED 7007/demo       
root@ubuntu:~# 
```

其中

- Proto ：网络传输协议，主要为tcp和udp
- Local Address ：本地的ip:port
- Foreign Address：远程主机的ip:port
- State ：连线状态，主要有监听（ LISTEN ）和建立（ESTABLISED）
- PID ：服务的进程编号
- Program name：服务名称