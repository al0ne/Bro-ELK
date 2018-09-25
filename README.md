# Bro-ELK
### 安装配置
具体的安装过程就不在描述了，官网上面的文档很详细，这里主要就是讲讲如何把bro解析的日志导出到ELK里面，之前在github搜别人贴的配置文件发现还是有一些坑。

### 禁用协议
在安装bro后实际我们用不着那么多协议解析，尤其是在大流量环境下很费性能
在/usr/local/bro/share/bro/site/目录下创建disable_analyzer.bro

    event bro_init()
        {
        Log::disable_stream(X509::LOG);
        Log::disable_stream(Weird::LOG);
        Log::disable_stream(Files::LOG);
        }
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_AYIYA };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_DCE_RPC };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_DHCP };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_DNP3_TCP };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_IRC };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_IRC_DATA };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_MODBUS };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_XMPP };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_SYSLOG };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_SIP };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_RFB };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_RADIUS };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_NCP };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_SNMP };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_TEREDO };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_FTP_DATA };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_FTP };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_BACKDOOR };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_DNP3_UDP };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_FINGER };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_GNUTELLA };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_GSSAPI };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_GTPV1 };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_IDENT };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_NVT };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_PIA_TCP };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_PIA_UDP };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_SIP };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_NCP };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_NFS };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_BITTORRENTTRACKER };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_FTP_ADAT };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_POP3 };
    redef Analyzer::disabled_analyzers += { Analyzer::ANALYZER_STEPPINGSTONE };
    
然后在local.bro添加

    @load disable_analyzer.bro


### 安装配置
在安装bro与elk后，首先我们要将bro的日志改成json格式，默认是以TAB分隔

在/usr/local/bro/share/bro/policy/tuning下面新建json-logs.bro

    redef LogAscii::use_json=T;
然后在/usr/local/bro/share/bro/site/local.bro里面添加

     @load policy/tuning/json-logs.bro

将logstash.conf配置文件放到/etc/logstash/conf.d/bro.conf，然后运行logstash -f 加载配置文件

### 参考来源
https://www.bro.org

https://doc.yonyoucloud.com/doc/logstash-best-practice-cn/index.html

https://github.com/timmolter/logstash-dfir/tree/master/conf_files/bro
