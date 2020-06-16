# mongo-config-yaml
the configuration file of mongo(mongo配置文件)

mongodb yaml格式配置文件demo: 

```yaml
systemLog: #日志设置
   destination: file #日志记录，file或者syslog，如果指定为file，需要同时指定path
   path: "/usr/local/var/log/mongod.log" #日志目录
   logAppend: true  #日志以追加的形式记录
processManagement: #进程管理
   fork: false  #是否开启daemon模式
   pidFilePath: "/var/run/mongod.pid" #pid文件存放位置，注意目录权限
net:
   bindIp: 127.0.0.1 #默认localhost，如果需要添加多个，使用,分割，支持IPV6，需要设置ipv6为true
   port: 27017 
   maxIncomingConnections: 20 #接受的最大连接数
storage: #存储设置
   dbPath: "/usr/local/mongodb/db" #db存放位置
   journal:   #journal设置
      enabled: true
   engine: wiredTiger #存储引擎设置，默认wiredTiger
   wiredTiger:
      engineConfig:
         cacheSizeGB: 2 #给存储引擎配置的内存数量
security: #是否开启用户验证
   authorization: enabled
```

**开启用户验证前需要先建立root用户**

```
>use admin;
>db.createUser({
    user:"root",
    pwd:"****",
    roles:[
        { 
            role:"root",
            db:"admin"
        }
    ]
})
```