# mongo-config-yaml
the configuration file of mongo(mongo配置文件)

mongodb yaml格式配置文件demo: 

各个配置项的详细介绍请跳转[MongoDB官网](https://docs.mongodb.com/manual/reference/configuration-options/#security.kmip.clientCertificateFile)

```yaml
systemLog: #日志设置
    verbosity: 1 #默认值0，日志输出详细度，1-5日志越来越细
    quiet: false #静默模式，限制输出，生产环境中不建议设置为true
    traceAllExceptions: true #打印详细的调试信息
    syslogFacility: "root" #记录日志的设备级别，如果设置了此项，必须将systemLog.destination设置为syslog
    path: "/usr/local/var/log/mongod.log" #mongodb日志的存放目录
    logAppend: true  #为true，则mongodb每次重启时日志都会以追加的形式记录到文件里，否则则会备份既有的文件，并且重新创建新的日志文件
    logRotate: "reopen" #rename：重命名日志文件 reopen：按照Linux/Unix日志反转行为来关闭或者重新打开日志文件，设置为reopen时必须同时设置systemLog.logAppend为true
    destination: file #日志记录，file或者syslog，如果指定为file，需要同时指定path，如果没有设置此项，则所有日志都将被输出到标准输出，为了保证精确的时间，生产环境建议配置为file
    timeStampFormat: "iso8601-local" #日志信息的时间格式，ctime(格式为Wed Dec 31 18:17:54.811), iso8601-utc(格式为1970-01-01T00:00:00.000Z), iso8601-local(格式为1969-12-31T19:00:00.000-0500) 
processManagement: #进程管理
    fork: false  #是否开启daemon模式
    pidFilePath: "/var/run/mongod.pid" #pid文件存放位置，注意目录权限
    timeZoneInfo: "/usr/share/zoneinfo" #时区数据库，如果没配置，则mongo会使用内置的时区数据库，linux和macOs默认设置为/usr/share/zoneinfo
    windowsService: #windowns系统上的相关配置
        serviceName: MongoDB #作为windows服务运行是的服务名
        displayName: MongoDB #在Windows系统中Services administrative application展示的名字
        description: 
        serviceUser:
        servicePassword:
cloud: #4.0版本新功能
    monitoring:
        free:
            state: runtime #runtime: 运行中可以启用或者停用免费监控; on: 启动时开启免费监控，运行时无法停用; off: 启动时停用免费监控，运行时无法启用
            tags: ""
net: #网络配置
    port: 27017 #端口  
    bindIp: 127.0.0.1 #从v3.6开始默认值为localhost，如果需要添加多个，使用,分割，支持IPV6，需要设置ipv6为true
    bindIpAll: false #v3.6之后支持，为true时支持所有的IPV4，如果设置ipv6为true，则也支持所有的ipv6，注意：暴露在公网时，需要防止未授权的访问
    maxIncomingConnections: 65536 #同时接受的最大连接数，不要将此项的值设置得太低，否则会遇到错误在正常操作时
    wireObjectCheck: false #如果为true，会阻止客户端插入畸形或者无效的BSON数据到数据库
    ipv6: true #支持IPV6，默认不支持
    unixDomainSocket:
        enabled: false #默认值true，仅适用于类unix系统，启用或停用Unix域套接字通信
        pathPrefix: "/tmp" #默认值/tmp, 如果没设置，则会创建以/tmp为前缀的socket
        filePermissions: 0700 #socket file文件的权限
    tls: 
      mode: disabled #disabled: 不使用TLS  allowTLS: 服务之间不使用TLS, 客户端连接同时支持TLS和非TLS  preferTLS: 服务之间使用TLS，客户端都支持  requireTLS: 只接受TLS加密的连接
      certificateKeyFile: "/usr/local/etc/test.pem" #同时包含证书和密钥的.pem文件，如果TLS开启，Linux系统必须指定certificateKeyFile，windows和macOS系统必须指定certificateKeyFile和certificateSelector中的一个
      certificateKeyFilePassword: "test" #用于解密证书文件的密码
      certificateSelector: subject="证书名" #从系统证书目录中选取匹配的证书
      clusterCertificateSelector: subject="证书名" #
      clusterFile: "/usr/local/etc/test.pem" 
      clusterPassword: "" #解密clusterFile证书的密码
      CAFile: "/usr/local/etc/rootCA.pem" #根证书
      clusterCAFile: "/usr/local/etc/rootCA.pem"
      CRLFile: "" #证书吊销列表
      allowConnectionsWithoutCertificates: false #是否允许客户端连接不通过TLS/SSL证书建立连接
      allowInvalidCertificates: false #是否允许验证非法证书建立连接
      allowInvalidHostnames: false #如果设置为true，将禁用证书中的主机名，如果证书主机名不匹配也允许建立连接
      disabledProtocols: TLS1_0,TLS1_1,TLS1_2,TLS1_3 #拒绝接受的TLS连接类型
      FIPSMode: true #禁用或者启用FIPS模式，前提是系统有支持FIPS的库
    compression: 
        compressors: snappy,zstd,zlib #network compression，不需要时设置为disabled
    serviceExecutor: synchronous #执行客户端请求的模式：synchronous或者adaptive
security: #是否开启用户验证
    keyFile: "/usr/local/etc/keyfile" #集群之间相互验证的key
    clusterAuthMode: keyFile #集群的认证的模式：keyFile, sendKeyFile, sendX509, x509
    authorization: enabled #用户对数据库的访问权限认证: enabled, disabled
    transitionToAuth: false #是否允许实例接受和创建认证或非认证的连接
    javascriptEnabled: true #启用或者禁用服务侧端的JavaScript代码执行
    redactClientLogData: false #阻止mongo将潜在的敏感数据写进log
    clusterIpSourceWhitelist:  #白名单，不对白名单内的IP做认证
        - 192.0.2.0/24
        - 127.0.0.1
        - ::1
    sasl:
        hostName: #SASL域名
        serviceName: #SASL服务名
        saslauthdSocketPath:  #SASL socket UNIX domain
    enableEncryption: false #当engine为WiredTiger时，开启加密。只对企业版可用
    encryptionCipherMode: AES256-CBC #加密模式：AES256-CBC, AES256-GCM
    encryptionKeyFile: #本地密钥文件，只当设置为进程管理密钥时有效，如果数据已经被KMIP加密了，会报错
    kmip: #企业版功能
        keyIdentifier: #KMIP标示，企业版功能，security.enableEncryption需要设置为true
        rotateMasterKey: false #设置为true时，旋转master key 并且重新加密internal keystore
        serverName: localhost #KMIP服务连接地址，需要security.enableEncryption设置为true
        port: 5696 #需要提供security.kmip.serverName，并且需要security.enableEncryption设置为true
        clientCertificateFile: #企业版功能，客户端证书文件，用于验证KMIP server
        clientCertificatePassword: #企业版功能，加密clientCertificateFile文件的密钥
        clientCertificateSelector:  #企业版功能，security.kmip.clientCertificateFile和 security.kmip.clientCertificateSelector只需要设置一个
        serverCAFile: #CA证书路径，用于保证客户端连接KMIP
    ldap:
        servers: #LDAP server， 决定用户对给定数据库有那些操作权限
        bind:
            method: simple #使用queryUser和queryPassword连接LDAP时的方法，sample或者sasl
            saslMechanisms: DIGEST-MD5 #GSSAPI或者DIGEST-MD5，mongo用来验证LDAP服务的机构，method设置为sasl时设置
            queryUser:  #当连接LDAP或者查询时的身份标示，如果没有设置，mongo将不会试图监听LDAP服务
            queryPassword: #使用queryUser时的密码
            useOSDefaults: false #当连接LDAP服务时，允许mongo使用windows登录凭证
        transportSecurity: tls #mongo默认为LDAP创建TLS/SSL安全连接
        timeoutMS: 10000 #LDAP响应超时，毫秒
        userToDNMapping: [
                            {
                               match: "(.+)@ENGINEERING.EXAMPLE.COM",
                               substitution: "cn={0},ou=engineering,dc=example,dc=com"
                            },
                            {
                               match: "(.+)@DBA.EXAMPLE.COM",
                               ldapQuery: "ou=dba,dc=example,dc=com??one?(user={0})"
                         
                            }
                         
                         ] #提供给mongo认证LDAP Distinguished Name的用户列表
        authz:
            queryTemplate: {USER}?memberOf?base #
        validateLDAPServerConfig: true #是否开启LDAP服务可用性检测
setParameter: #使用如下格式设置mongo的参数
    enableLocalhostAuthBypass: false
    ldapUserCacheInvalidationInterval: 30
storage: #存储设置
    dbPath: "/usr/local/mongodb/db" #db存放位置, 注意windows中的格式为：\data\db
    indexBuildRetry: true #下次启动时是否重新编译未完成的索引，对使用 in-memory storage engine的mongo实例不可用
    journal:   #journal设置
        enabled: true #64位系统默认位true，32位系统默认位false，启用或禁用journal保证数据文件可用和可恢复
        commitIntervalMs: 100  #journal操作之间的最大时间间隔（1-500）, 毫秒
    directoryPerDB: false # 设置为true时，mongo会在dbpath下为每个数据库设置单独的存放目录
    syncPeriodSecs: 60 #mongo同步数据到文件时的时间间隔，不要在生产环境中设置此值
    engine: wiredTiger #wiredTiger, inMemory. 存储引擎设置，默认wiredTiger
    wiredTiger:
        engineConfig:
            cacheSizeGB: 2 #给存储引擎配置的内存数量，单位GB
            journalCompressor: snappy #压缩WiredTiger journal数据的类型：none, snappy, zlib, zstd
            directoryForIndexes: false #设置为true时，mongo在data目录下使用单独的子目录存放索引和集合
            maxCacheOverflowFileSizeGB: 0 #为“lookaside (or cache overflow) table”设置最大值，设置值>=0.1， 可在运行过程中设置。
        collectionConfig:
            blockCompressor: none #压缩集合数据的默认压缩类型：none, snappy, zlib, zstd
        indexConfig:
            prefixCompression: true #启用或者禁用prefixCompression，通过一次存放相同的索引前缀来减少内存或者硬盘消耗
    inMemory:
        engineConfig:
            inMemorySizeGB: 2 #in-memory存储引擎数据可分配的最大内存，包括索引，也包括操作日志（前提是如果mongo是replica set，或者replica set的一部分或者集群元数据时）
operationProfiling: #慢查询配置
    mode: off #Database Profiler收集数据库指令的详细信息，可选值: off(关闭，不收集任何数据), slowOp(收集耗时超过slowms的操作), all(收集所有), 
    slowOpThresholdMs: 100 #运行时间超多此值的操作被视为slow，单位毫秒
    slowOpSampleRate: 1.0 #0-1.0, 应该被profiled或者logged的慢操作部分
replication: #副本相关配置
    oplogSizeMB: #响应操作日志的最大值，单位MB
    replSetName: #mongo所属的replica set的名字，replica set中所有hosts应该有相同的set名字，如果你的应用连接超多1个replica set，每个set应该有唯一的名字
    enableMajorityReadConcern: true #防止PSA部署架构停止运转带给存储缓存的压力，设置为false
    localPingThresholdMs: 15 #此项只针对mongos。 ping时间，毫秒。mongos用来查找第二个处理来自客户端读取操作的replica set成员
sharding: #分片集配置
    clusterRole: configsvr #mongo实例在集群中的角色，可选值: configsvr(作为配置服务启动实例，默认在27019端口启动), shardsvr(作为shard启动，默认以27018端口启动)
    archiveMovedChunks: false #
    configDB: <configReplSetName>/cfg1.example.net:27019 #此项只针对mongos。指定config server的replica set名字，hostname和端口
auditLog: #审计日志配置
    destination: syslog #syslog(以JSON格式输出审核事件到syslog, Windows系统不可用) console(以JSON格式输出审核事件到标准输出) file(以auditLog.format格式输出到auditLog.path指定的目录) 
    format: JSON #auditLog输出格式，对应destination设置为file的话，此项生效，另一个可选值是BSON
    path: "/var/log/audit.log" #auditLog存放路径，对应destination设置为file的话，此项生效
    filter: {atype: "$eq"} #过滤audit system记录的操作类型
snmp: #SNMP配置
    disabled: false #是否禁止SNMP访问mongo
    subagent: true #如果设置为true且snmp.disabled设置为false, 则SNMP作为subagent运行，如果snmp.disabled设置为true，则此项无效 
    master: false #如果设置为true且snmp.disabled设置为false, 则SNMP作为master运行，如果snmp.disabled设置为true，则此项无效
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