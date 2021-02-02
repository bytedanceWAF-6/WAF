# mysql

启动mysql：`service mysql start`
停止mysql：`service mysql stop`
重启mysql：`service mysql restart`

登录` mysql -u root -p`

pw 123456

# nginx

> 登录

cd /usr/local/nginx/sbin

./nginx

> 停止

./nginx -s stop

> 重新加载配置文件

./nginx -s reload

> 查看nginx进程

ps aux|grep nginx

# OpenResty

OpenResty(又称：ngx_openresty) 是一个基于 NGINX 的可伸缩的 Web 平台，由中国人章亦春发起，提供了很多高质量的第三方模块。

OpenResty 是一个强大的 Web 应用服务器，Web 开发人员可以使用 Lua 脚本语言调动 Nginx 支持的各种 C 以及 Lua 模块,更主要的是在性能方面，OpenResty可以 快速构造出足以胜任 10K 以上并发连接响应的超高性能 Web 应用系统。

360，UPYUN，阿里云，新浪，腾讯网，去哪儿网，酷狗音乐等都是 OpenResty 的深度用户。

## 从OpenResty启动nginx

cd /usr/local/openresty/nginx

其它命令与nginx一样
