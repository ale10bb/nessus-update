# Nessus Update

Nessus Scanner 的更新工具

## 快速使用

1. 找负责nessus的管理员，把更新地址改成``xxx.nessus-update.chenql.cn``（xxx是自己的邮箱username）。
2. 找服务器管理员添加反向代理路径。
3. 打开默认``nessus-update.conf``并修改以下xxx处
   - ``[nessus]``节中设置客户端的username和password
   - ``[v2ray]``节中设置user（自己的邮箱username）
4. 打开nessus-update.exe，开在后台（不用关本机防火墙）
5. 找nessus管理员发起更新推送，或者等SC自动下发更新（每15分钟下发一次）。更新时控制台有日志输出。一般更新包需要传输3-10分钟不等，并花费10分钟至20分钟安装，安装时占用所有CPU和大量磁盘I/O，请耐心等待。

## 高级功能

### OSS缓存

在线更新时，服务器将尝试缓存完整插件包``all-2.0.tar.gz``至OSS。更新工具启动时会从OSS读取缓存的插件包版本，如果版本较新，将提示用户从OSS下载插件包进行离线更新（下载速度将比在线更新快）。下载的插件包``all-2.0.tar.gz``保存在工具同目录。

OSS缓存的地址可在配置文件的``[oss]``节中设置。当前默认下载地址为：

- [http://static.chenql.cn/nessus/all-2.0.tar.gz](http://static.chenql.cn/nessus/all-2.0.tar.gz)

### 离线更新

工具支持离线更新功能。如果本地已经有完整插件包``all-2.0.tar.gz``，更新工具启动时会校验其有效性。如果插件包有效，将进入离线更新模式。

离线更新时，工具读取``[nessus]``节的所有参数，并尝试登录Scanner。更新本机Scanner时，host默认设置为``127.0.0.1``，也无需关闭防火墙。如果需要更新其他Scanner，需保证对方的Scanner网络地址（如``https://192.168.1.2:8834``）可以访问，必要时让对方关闭防火墙。

- 注：Scanner的端口必须为8834

### 反向代理

在线更新功能由反向代理服务器 (v2ray) 实现，v2ray的参数可在配置文件的``[v2ray]``节中设置。当前默认配置项为：

- ``address`` nessus-update.chenql.cn
- ``port`` 8835

反向代理客户端依赖``v2ray-core:v5``，需从其[Github Release](https://github.com/v2fly/v2ray-core/releases)下载``v2ray-windows-64.zip``后，解压``v2ray.exe``文件放在工具同目录。
## 更新原理

对于由SC控制的Nessus Scanner，SC大约每15分钟发送心跳包检测客户端存活情况，并在必要时更新客户端特征库（Plugin Set）。若特征库版本差值小于某个值（大约一个月），SC将下发差异更新包，文件名类似``diff-since-xx``。若特征库一个月以上没有更新，SC将下发完整更新包``all-2.0.tar.gz``。

一般完整更新包需要花费10分钟至20分钟更新，更新时占用所有CPU和大量磁盘I/O。
