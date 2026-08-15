"""Curated FOFA library rules using official `app=` syntax from https://fofa.info/library."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class FofaRule:
    name: str
    query: str
    category: str
    aliases: tuple[str, ...] = ()


# Public `app=` names from FOFA 规则列表. High-value subset for OA / 中间件 / 面板 / VPN, not a dump of the whole library.
LIBRARY_RULES: tuple[FofaRule, ...] = (
    # Web / 开发框架
    FofaRule("ThinkPHP", 'app="ThinkPHP"', "框架", ("thinkphp", "tp")),
    FofaRule("Laravel", 'app="Laravel"', "框架", ("laravel",)),
    FofaRule("Django", 'app="Django"', "框架", ("django",)),
    FofaRule("Flask", 'app="Flask"', "框架", ("flask",)),
    FofaRule("FastAPI", 'app="FastAPI"', "框架", ("fastapi",)),
    FofaRule("Spring", 'app="Spring"', "框架", ("spring", "springboot", "spring-boot", "spring boot")),
    FofaRule("Struts2", 'app="Struts2"', "框架", ("struts", "struts2")),
    FofaRule("ASP.NET", 'app="ASP.NET"', "框架", ("asp.net", "aspx")),
    FofaRule("Node.js", 'app="Node.js"', "框架", ("nodejs", "node.js")),
    FofaRule("Express", 'app="Express"', "框架", ("express.js", "expressjs", "express")),
    FofaRule("Yii", 'app="Yii"', "框架", ("yii", "yii2")),
    FofaRule("CodeIgniter", 'app="CodeIgniter"', "框架", ("codeigniter",)),
    FofaRule("Symfony", 'app="Symfony"', "框架", ("symfony",)),
    FofaRule("Ruby on Rails", 'app="Ruby-on-Rails"', "框架", ("rails", "ror")),
    FofaRule("Beego", 'app="Beego"', "框架", ("beego",)),
    FofaRule("Gin", 'app="Gin"', "框架", ("gin-gonic", "gin")),
    FofaRule("Dubbo", 'app="Dubbo"', "框架", ("dubbo",)),
    FofaRule("Shiro", 'app="Shiro"', "框架", ("shiro", "apache shiro")),
    FofaRule("Fastjson", 'app="Fastjson"', "框架", ("fastjson",)),
    FofaRule("MyBatis", 'app="MyBatis"', "框架", ("mybatis",)),
    FofaRule("Hibernate", 'app="Hibernate"', "框架", ("hibernate",)),
    FofaRule("Vue", 'app="Vue.js"', "框架", ("vue", "vuejs", "vue.js")),
    FofaRule("React", 'app="React"', "框架", ("react", "reactjs")),
    FofaRule("Bootstrap", 'app="Bootstrap"', "框架", ("bootstrap",)),
    FofaRule("ThinkCMF", 'app="ThinkCMF"', "框架", ("thinkcmf",)),
    FofaRule("JeecgBoot", 'app="JeecgBoot"', "框架", ("jeecg", "jeecgboot")),
    FofaRule("RuoYi", 'app="RuoYi"', "框架", ("ruoyi", "若依")),
    FofaRule("Knife4j", 'app="Knife4j"', "框架", ("knife4j", "swagger-bootstrap")),
    FofaRule("Swagger", 'app="Swagger"', "运维面板", ("swagger", "openapi")),
    # 中间件 / 服务器
    FofaRule("Nginx", 'app="Nginx"', "中间件", ("nginx",)),
    FofaRule("Apache", 'app="Apache"', "中间件", ("apache", "httpd")),
    FofaRule("Apache Tomcat", 'app="Apache Tomcat"', "中间件", ("tomcat",)),
    FofaRule("Microsoft-IIS", 'app="Microsoft-IIS"', "中间件", ("iis",)),
    FofaRule("WebLogic", 'app="WebLogic"', "中间件", ("weblogic",)),
    FofaRule("JBoss", 'app="JBoss"', "中间件", ("jboss", "wildfly")),
    FofaRule("Jetty", 'app="Jetty"', "中间件", ("jetty",)),
    FofaRule("OpenResty", 'app="OpenResty"', "中间件", ("openresty",)),
    FofaRule("Tengine", 'app="Tengine"', "中间件", ("tengine",)),
    FofaRule("Caddy", 'app="Caddy"', "中间件", ("caddy",)),
    FofaRule("Lighttpd", 'app="lighttpd"', "中间件", ("lighttpd",)),
    FofaRule("Resin", 'app="Resin"', "中间件", ("resin",)),
    FofaRule("GlassFish", 'app="GlassFish"', "中间件", ("glassfish",)),
    FofaRule("TongWeb", 'app="TongWeb"', "中间件", ("tongweb", "东方通")),
    FofaRule("BES", 'app="BES"', "中间件", ("bes中间件", "宝兰德")),
    FofaRule("WebSphere", 'app="IBM-WebSphere"', "中间件", ("websphere", "was")),
    FofaRule("Undertow", 'app="Undertow"', "中间件", ("undertow",)),
    FofaRule("HAProxy", 'app="HAProxy"', "中间件", ("haproxy",)),
    FofaRule("Traefik", 'app="Traefik"', "中间件", ("traefik",)),
    FofaRule("Squid", 'app="Squid"', "中间件", ("squid",)),
    FofaRule("Varnish", 'app="Varnish"', "中间件", ("varnish",)),
    FofaRule("IIS-FTP", 'app="Microsoft-FTP"', "中间件", ("iis ftp",)),
    # 数据存储
    FofaRule("Redis", 'app="Redis"', "数据存储", ("redis",)),
    FofaRule("MySQL", 'app="MySQL"', "数据存储", ("mysql", "mariadb")),
    FofaRule("PostgreSQL", 'app="PostgreSQL"', "数据存储", ("postgres", "postgresql")),
    FofaRule("MongoDB", 'app="MongoDB"', "数据存储", ("mongo", "mongodb")),
    FofaRule("Elasticsearch", 'app="Elasticsearch"', "数据存储", ("elasticsearch", "elastic")),
    FofaRule("Microsoft SQL Server", 'app="Microsoft-SQL-Server"', "数据存储", ("mssql", "sqlserver", "sql server")),
    FofaRule("Oracle", 'app="Oracle"', "数据存储", ("oracle", "oracle db", "oracle database")),
    FofaRule("Kafka", 'app="Kafka"', "数据存储", ("kafka",)),
    FofaRule("RabbitMQ", 'app="RabbitMQ"', "数据存储", ("rabbitmq",)),
    FofaRule("Memcached", 'app="Memcached"', "数据存储", ("memcached",)),
    FofaRule("ClickHouse", 'app="ClickHouse"', "数据存储", ("clickhouse",)),
    FofaRule("CouchDB", 'app="CouchDB"', "数据存储", ("couchdb",)),
    FofaRule("InfluxDB", 'app="InfluxDB"', "数据存储", ("influxdb", "influx")),
    FofaRule("Neo4j", 'app="Neo4j"', "数据存储", ("neo4j",)),
    FofaRule("Cassandra", 'app="Cassandra"', "数据存储", ("cassandra",)),
    FofaRule("Solr", 'app="Apache-Solr"', "数据存储", ("solr", "apache solr")),
    FofaRule("ZooKeeper", 'app="Apache-ZooKeeper"', "数据存储", ("zookeeper", "zk")),
    FofaRule("ActiveMQ", 'app="Apache-ActiveMQ"', "数据存储", ("activemq",)),
    FofaRule("RocketMQ", 'app="RocketMQ"', "数据存储", ("rocketmq",)),
    FofaRule("HBase", 'app="HBase"', "数据存储", ("hbase",)),
    FofaRule("Hive", 'app="Apache-Hive"', "数据存储", ("hive",)),
    FofaRule("TiDB", 'app="TiDB"', "数据存储", ("tidb",)),
    FofaRule("达梦", 'app="DM-Database"', "数据存储", ("达梦", "dameng")),
    FofaRule("人大金仓", 'app="Kingbase"', "数据存储", ("人大金仓", "kingbase")),
    FofaRule("OpenSearch", 'app="OpenSearch"', "数据存储", ("opensearch",)),
    FofaRule("Druid监控", 'app="Alibaba-Druid"', "数据存储", ("druid监控", "alibaba druid")),
    FofaRule("Apache Druid", 'app="Apache-Druid"', "数据存储", ("apache druid",)),
    # OA / ERP
    FofaRule("致远OA", 'app="致远互联-OA"', "OA", ("seeyon", "zhiyuan", "致远")),
    FofaRule("泛微OA", 'app="泛微-协同办公OA"', "OA", ("weaver", "ecology", "泛微")),
    FofaRule("泛微E-Office", 'app="泛微-EOffice"', "OA", ("e-office", "eoffice", "泛微eoffice")),
    FofaRule("通达OA", 'app="通达OA"', "OA", ("tongda", "通达")),
    FofaRule("用友NC", 'app="用友-UFIDA-NC"', "OA", ("yonyou nc", "ufida", "用友nc")),
    FofaRule("用友U8", 'app="用友-U8"', "OA", ("用友u8", "u8 erp")),
    FofaRule("用友GRP", 'app="用友-GRP-U8"', "OA", ("用友grp", "grp-u8")),
    FofaRule("用友畅捷通", 'app="用友畅捷通"', "OA", ("畅捷通", "chanjet")),
    FofaRule("金蝶EAS", 'app="金蝶"', "OA", ("kingdee", "金蝶")),
    FofaRule("金蝶云星空", 'app="金蝶云星空"', "OA", ("金蝶云", "星空")),
    FofaRule("金蝶K3", 'app="金蝶-K3"', "OA", ("金蝶k3", "k3 wise")),
    FofaRule("蓝凌OA", 'app="蓝凌软件"', "OA", ("landray", "蓝凌")),
    FofaRule("万户OA", 'app="万户网络-ezOFFICE"', "OA", ("万户", "ezoffice")),
    FofaRule("华天动力OA", 'app="华天动力-OA"', "OA", ("华天动力",)),
    FofaRule("金和OA", 'app="金和网络-金和OA"', "OA", ("金和", "jinher")),
    FofaRule("红帆OA", 'app="红帆-ioffice"', "OA", ("红帆", "ioffice")),
    FofaRule("新点OA", 'app="新点OA"', "OA", ("新点", "sundray oa")),
    FofaRule("协众OA", 'app="协众OA"', "OA", ("协众",)),
    FofaRule("信呼OA", 'app="信呼OA"', "OA", ("信呼", "xinhu")),
    FofaRule("一米OA", 'app="一米OA"', "OA", ("一米",)),
    FofaRule("SAP NetWeaver", 'app="SAP-NetWeaver"', "OA", ("sap", "netweaver")),
    FofaRule("Odoo", 'app="Odoo"', "OA", ("odoo", "openerp")),
    FofaRule("浪潮GS", 'app="浪潮-GS"', "OA", ("浪潮gs", "langchao")),
    FofaRule("用友NC Cloud", 'app="用友-NC-Cloud"', "OA", ("nc cloud", "用友云")),
    FofaRule("泛微E-cology", 'app="泛微-ecology"', "OA", ("e-cology", "ecology oa")),
    FofaRule("致远A8", 'app="致远互联-A8"', "OA", ("致远a8", "a8+", "seeyon a8")),
    FofaRule("宏景HR", 'app="宏景-HR"', "OA", ("宏景",)),
    FofaRule("明源云", 'app="明源云"', "OA", ("明源",)),
    FofaRule("广联达", 'app="广联达"', "OA", ("广联达", "glodon")),
    FofaRule("帆软报表", 'app="FineReport"', "OA", ("帆软", "finereport", "finebi")),
    FofaRule("禅道", 'app="禅道"', "OA", ("zentao", "禅道")),
    # VPN / 网关 / 安全设备
    FofaRule("深信服VPN", 'app="SANGFOR-SSL-VPN"', "网络设备", ("sangfor", "深信服", "ssl vpn")),
    FofaRule("深信服NGAF", 'app="SANGFOR-NGAF"', "网络设备", ("深信服防火墙", "sangfor ngaf")),
    FofaRule("深信服AD", 'app="SANGFOR-应用交付AD"', "网络设备", ("深信服ad", "sangfor ad")),
    FofaRule("奇安信VPN", 'app="奇安信-VPN"', "网络设备", ("qianxin", "奇安信")),
    FofaRule("奇安信天擎", 'app="奇安信-天擎"', "网络设备", ("天擎", "qax")),
    FofaRule("Fortinet", 'app="FORTINET-防火墙"', "网络设备", ("fortigate", "fortinet")),
    FofaRule("FortiSSLVPN", 'app="FORTINET-SSLVPN"', "网络设备", ("fortisslvpn", "fortigate vpn")),
    FofaRule("Cisco ASA", 'app="CISCO-ASA"', "网络设备", ("cisco asa", "asa")),
    FofaRule("Pulse Secure", 'app="PULSE-SECURE-VPN"', "网络设备", ("pulse secure", "ivanti")),
    FofaRule("Array VPN", 'app="Array-VPN"', "网络设备", ("array vpn", "array networks")),
    FofaRule("H3C", 'app="H3C-实体防火墙"', "网络设备", ("h3c", "新华三")),
    FofaRule("Ruijie", 'app="Ruijie"', "网络设备", ("ruijie", "锐捷")),
    FofaRule("天融信VPN", 'app="天融信-VPN"', "网络设备", ("天融信", "topsec")),
    FofaRule("启明星辰", 'app="Venustech"', "网络设备", ("启明星辰", "venustech", "天清")),
    FofaRule("绿盟WAF", 'app="NSFOCUS-WAF"', "网络设备", ("绿盟", "nsfocus")),
    FofaRule("安恒明御", 'app="安恒信息-明御WAF"', "网络设备", ("安恒", "明御", "dbappsecurity")),
    FofaRule("长亭WAF", 'app="长亭科技-WAF"', "网络设备", ("长亭", "chaitin")),
    FofaRule("雷池WAF", 'app="SafeLine"', "网络设备", ("雷池", "safeline")),
    FofaRule("Palo Alto", 'app="PaloAlto-防火墙"', "网络设备", ("palo alto", "pan-os", "globalprotect")),
    FofaRule("Check Point", 'app="Check_Point"', "网络设备", ("checkpoint", "check point")),
    FofaRule("SonicWall", 'app="SONICWALL-SSL-VPN"', "网络设备", ("sonicwall",)),
    FofaRule("F5 BIG-IP", 'app="F5-BIGIP"', "网络设备", ("f5", "big-ip", "bigip")),
    FofaRule("Citrix ADC", 'app="Citrix-NetScaler"', "网络设备", ("citrix", "netscaler", "adc")),
    FofaRule("OpenVPN", 'app="OpenVPN"', "网络设备", ("openvpn",)),
    FofaRule("山石网科", 'app="Hillstone"', "网络设备", ("山石", "hillstone")),
    FofaRule("360天擎", 'app="360天擎"', "网络设备", ("360天擎", "qianxin 360")),
    FofaRule("Cloudflare", 'app="Cloudflare"', "网络设备", ("cloudflare",)),
    # 邮件 / 协作
    FofaRule("Microsoft Exchange", 'app="Microsoft-Exchange"', "邮件协作", ("exchange", "owa", "outlook web")),
    FofaRule("Zimbra", 'app="Zimbra"', "邮件协作", ("zimbra",)),
    FofaRule("Roundcube", 'app="Roundcube"', "邮件协作", ("roundcube",)),
    FofaRule("Coremail", 'app="Coremail"', "邮件协作", ("coremail", "论客")),
    FofaRule("亿邮", 'app="亿邮"', "邮件协作", ("eyou", "亿邮")),
    FofaRule("RainLoop", 'app="RainLoop"', "邮件协作", ("rainloop",)),
    FofaRule("SquirrelMail", 'app="SquirrelMail"', "邮件协作", ("squirrelmail",)),
    FofaRule("IceWarp", 'app="IceWarp"', "邮件协作", ("icewarp",)),
    FofaRule("Confluence", 'app="Confluence"', "邮件协作", ("confluence",)),
    FofaRule("Jira", 'app="JIRA"', "邮件协作", ("jira",)),
    FofaRule("ShowDoc", 'app="ShowDoc"', "邮件协作", ("showdoc",)),
    FofaRule("YApi", 'app="YApi"', "邮件协作", ("yapi",)),
    FofaRule("Nextcloud", 'app="Nextcloud"', "邮件协作", ("nextcloud",)),
    FofaRule("ownCloud", 'app="ownCloud"', "邮件协作", ("owncloud",)),
    FofaRule("Seafile", 'app="Seafile"', "邮件协作", ("seafile",)),
    FofaRule("可道云", 'app="KodExplorer"', "邮件协作", ("kodexplorer", "可道云", "kod")),
    # 监控 / 运维面板
    FofaRule("Grafana", 'app="Grafana"', "运维面板", ("grafana",)),
    FofaRule("Jenkins", 'app="Jenkins"', "运维面板", ("jenkins",)),
    FofaRule("GitLab", 'app="GitLab"', "运维面板", ("gitlab",)),
    FofaRule("Gitea", 'app="Gitea"', "运维面板", ("gitea",)),
    FofaRule("Gogs", 'app="Gogs"', "运维面板", ("gogs",)),
    FofaRule("Harbor", 'app="Harbor"', "运维面板", ("harbor",)),
    FofaRule("Nexus", 'app="Nexus"', "运维面板", ("nexus", "nexus repository")),
    FofaRule("Artifactory", 'app="Artifactory"', "运维面板", ("artifactory", "jfrog")),
    FofaRule("Kibana", 'app="Kibana"', "运维面板", ("kibana",)),
    FofaRule("phpMyAdmin", 'app="phpMyAdmin"', "运维面板", ("phpmyadmin", "pma")),
    FofaRule("Adminer", 'app="Adminer"', "运维面板", ("adminer",)),
    FofaRule("pgAdmin", 'app="pgAdmin"', "运维面板", ("pgadmin",)),
    FofaRule("Nacos", 'app="Nacos"', "运维面板", ("nacos",)),
    FofaRule("xxl-job", 'app="xxl-job"', "运维面板", ("xxljob", "xxl-job")),
    FofaRule("Apollo", 'app="Apollo"', "运维面板", ("apollo", "阿波罗配置")),
    FofaRule("Consul", 'app="Consul"', "运维面板", ("consul",)),
    FofaRule("Vault", 'app="Vault"', "运维面板", ("hashicorp vault", "vault")),
    FofaRule("Zabbix", 'app="ZABBIX"', "运维面板", ("zabbix",)),
    FofaRule("Prometheus", 'app="Prometheus"', "运维面板", ("prometheus",)),
    FofaRule("Webmin", 'app="Webmin"', "运维面板", ("webmin",)),
    FofaRule("宝塔", 'app="宝塔-BT.cn"', "运维面板", ("宝塔", "bt.cn", "bt panel")),
    FofaRule("1Panel", 'app="1Panel"', "运维面板", ("1panel",)),
    FofaRule("cPanel", 'app="cPanel"', "运维面板", ("cpanel",)),
    FofaRule("Plesk", 'app="Plesk"', "运维面板", ("plesk",)),
    FofaRule("JumpServer", 'app="JumpServer"', "运维面板", ("jumpserver", "jms")),
    FofaRule("Rancher", 'app="Rancher"', "运维面板", ("rancher",)),
    FofaRule("Portainer", 'app="Portainer"', "运维面板", ("portainer",)),
    FofaRule("SonarQube", 'app="SonarQube"', "运维面板", ("sonarqube", "sonar")),
    FofaRule("Airflow", 'app="Apache-Airflow"', "运维面板", ("airflow",)),
    FofaRule("Superset", 'app="Apache-Superset"', "运维面板", ("superset",)),
    FofaRule("Jupyter", 'app="Jupyter-Notebook"', "运维面板", ("jupyter", "jupyterlab")),
    FofaRule("DolphinScheduler", 'app="DolphinScheduler"', "运维面板", ("dolphinscheduler", "海豚调度")),
    FofaRule("Cacti", 'app="Cacti"', "运维面板", ("cacti",)),
    FofaRule("Nagios", 'app="Nagios"', "运维面板", ("nagios",)),
    FofaRule("Netdata", 'app="Netdata"', "运维面板", ("netdata",)),
    FofaRule("Uptime Kuma", 'app="Uptime-Kuma"', "运维面板", ("uptime kuma", "uptime-kuma")),
    FofaRule("Kubernetes Dashboard", 'app="Kubernetes-Dashboard"', "运维面板", ("k8s dashboard", "kubernetes dashboard")),
    FofaRule("phpStudy", 'app="phpStudy"', "运维面板", ("phpstudy",)),
    FofaRule("WDCP", 'app="WDCP"', "运维面板", ("wdcp",)),
    # 云原生 / 虚拟化
    FofaRule("Kubernetes", 'app="Kubernetes"', "云原生", ("k8s", "kubernetes")),
    FofaRule("Docker", 'app="Docker"', "云原生", ("docker", "docker api")),
    FofaRule("MinIO", 'app="MinIO"', "云原生", ("minio",)),
    FofaRule("etcd", 'app="etcd"', "云原生", ("etcd",)),
    FofaRule("VMware ESXi", 'app="VMware-ESXi"', "云原生", ("esxi", "vmware")),
    FofaRule("vCenter", 'app="VMware-vCenter"', "云原生", ("vcenter", "vsphere")),
    FofaRule("Proxmox", 'app="Proxmox-VE"', "云原生", ("proxmox", "pve")),
    FofaRule("OpenStack", 'app="OpenStack"', "云原生", ("openstack",)),
    FofaRule("Istio", 'app="Istio"', "云原生", ("istio",)),
    # 摄像头 / IoT
    FofaRule("海康威视", 'app="HIKVISION-视频监控"', "物联网", ("hikvision", "海康")),
    FofaRule("大华", 'app="Dahua-DH-IP"', "物联网", ("dahua", "大华")),
    FofaRule("宇视", 'app="Uniview"', "物联网", ("uniview", "宇视")),
    FofaRule("天地伟业", 'app="Tiandy"', "物联网", ("天地伟业", "tiandy")),
    FofaRule("Axis", 'app="AXIS"', "物联网", ("axis camera", "axis通讯")),
    FofaRule("Foscam", 'app="Foscam"', "物联网", ("foscam", "福斯康姆")),
    FofaRule("萤石", 'app="EZVIZ"', "物联网", ("萤石", "ezviz")),
    FofaRule("中威电子", 'app="TVT"', "物联网", ("中威", "tvt")),
    # CMS / 业务系统
    FofaRule("WordPress", 'app="WordPress"', "CMS", ("wordpress", "wp")),
    FofaRule("Discuz", 'app="Discuz"', "CMS", ("discuz", "discuz!")),
    FofaRule("Drupal", 'app="Drupal"', "CMS", ("drupal",)),
    FofaRule("Joomla", 'app="Joomla"', "CMS", ("joomla",)),
    FofaRule("DedeCMS", 'app="DedeCMS"', "CMS", ("dedecms", "织梦")),
    FofaRule("EmpireCMS", 'app="EmpireCMS"', "CMS", ("empirecms", "帝国cms")),
    FofaRule("PHPCMS", 'app="PHPCMS"', "CMS", ("phpcms",)),
    FofaRule("MetInfo", 'app="MetInfo"', "CMS", ("metinfo", "米拓")),
    FofaRule("Typecho", 'app="Typecho"', "CMS", ("typecho",)),
    FofaRule("Ghost", 'app="Ghost"', "CMS", ("ghost cms",)),
    FofaRule("PbootCMS", 'app="PbootCMS"', "CMS", ("pbootcms",)),
    FofaRule("ECShop", 'app="ECShop"', "CMS", ("ecshop",)),
    FofaRule("Magento", 'app="Magento"', "CMS", ("magento",)),
    FofaRule("ShopXO", 'app="ShopXO"', "CMS", ("shopxo",)),
    # NAS / 存储
    FofaRule("群晖", 'app="Synology"', "存储", ("synology", "群晖", "dsm")),
    FofaRule("QNAP", 'app="QNAP-NAS"', "存储", ("qnap", "威联通")),
    FofaRule("TrueNAS", 'app="TrueNAS"', "存储", ("truenas", "freenas")),
    FofaRule("OpenMediaVault", 'app="OpenMediaVault"', "存储", ("openmediavault", "omv")),
    # 远程办公
    FofaRule("向日葵", 'app="Oray"', "远程办公", ("向日葵", "sunlogin", "oray")),
    FofaRule("ToDesk", 'app="ToDesk"', "远程办公", ("todesk",)),
    FofaRule("RustDesk", 'app="RustDesk"', "远程办公", ("rustdesk",)),
    FofaRule("TeamViewer", 'app="TeamViewer"', "远程办公", ("teamviewer",)),
    FofaRule("AnyDesk", 'app="AnyDesk"', "远程办公", ("anydesk",)),
    FofaRule("Guacamole", 'app="Guacamole"', "远程办公", ("guacamole",)),
    # 大数据
    FofaRule("Hadoop", 'app="Hadoop"', "大数据", ("hadoop",)),
    FofaRule("Spark", 'app="Apache-Spark"', "大数据", ("apache spark", "spark")),
    FofaRule("Flink", 'app="Apache-Flink"', "大数据", ("flink", "apache flink")),
    FofaRule("Hue", 'app="Hue"', "大数据", ("cloudera hue",)),
    FofaRule("Ambari", 'app="Ambari"', "大数据", ("ambari",)),
    FofaRule("UEditor", 'app="UEditor"', "CMS", ("ueditor",)),
)


_GENERIC_TOKENS = frozenset({"oa", "vpn", "cms", "erp", "nas", "waf", "iot"})
_CATEGORY_PATTERNS: dict[str, tuple[str, ...]] = {
    "OA": (r"办公系统", r"协同办公", r"协同oa", r"(?<![a-z0-9])oa(?![a-z0-9])"),
    "中间件": (r"中间件", r"(?<![a-z0-9])middleware(?![a-z0-9])"),
    "数据存储": (r"数据库", r"(?<![a-z0-9])databases?(?![a-z0-9])"),
    "网络设备": (r"防火墙", r"安全网关", r"ssl\s*vpn", r"(?<![a-z0-9])vpn(?![a-z0-9])", r"(?<![a-z0-9])waf(?![a-z0-9])"),
    "邮件协作": (r"企业邮箱", r"邮件系统"),
    "运维面板": (r"运维面板", r"监控面板"),
    "云原生": (r"云原生", r"容器平台", r"容器编排"),
    "物联网": (r"摄像头", r"摄像机", r"监控设备", r"网络摄像机"),
    "CMS": (r"(?<![a-z0-9])cms(?![a-z0-9])", r"建站系统"),
    "存储": (r"(?<![a-z0-9])nas(?![a-z0-9])", r"网盘系统"),
    "远程办公": (r"远控软件", r"远程桌面软件"),
    "大数据": (r"大数据平台", r"hadoop生态"),
    "框架": (r"开发框架", r"web框架"),
}


def library_size() -> int:
    return len(LIBRARY_RULES)


def _ascii_token_in_text(token: str, text: str) -> bool:
    return re.search(rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])", text) is not None


def _token_in_text(token: str, text: str) -> bool:
    needle = token.strip().lower()
    if len(needle) < 2:
        return False
    if re.search(r"[\u4e00-\u9fff]", needle):
        return needle in text
    return _ascii_token_in_text(needle, text)


def _token_score(token: str) -> int:
    needle = token.strip().lower()
    if needle in _GENERIC_TOKENS:
        return 1
    if re.search(r"[\u4e00-\u9fff]", needle):
        return 10 + len(needle)
    return len(needle)


def match_intent_rules(text: str, *, limit: int = 8) -> list[FofaRule]:
    """Find library rules mentioned in a natural-language intent."""
    haystack = text.strip().lower()
    if not haystack:
        return []
    scored: list[tuple[int, FofaRule]] = []
    for rule in LIBRARY_RULES:
        best = 0
        for token in (rule.name, *rule.aliases):
            if _token_in_text(token, haystack):
                best = max(best, _token_score(token))
        if best:
            scored.append((best, rule))
    scored.sort(key=lambda item: (-item[0], item[1].name))
    strong = [rule for score, rule in scored if score >= 6]
    if strong:
        return strong[:limit]
    matched_categories = [
        category
        for category, patterns in _CATEGORY_PATTERNS.items()
        if any(re.search(pattern, haystack, re.IGNORECASE) for pattern in patterns)
    ]
    if matched_categories:
        return [rule for rule in LIBRARY_RULES if rule.category in matched_categories][:limit]
    return [rule for _, rule in scored[:limit]]


def rules_hint_for_prompt(intent: str, *, limit: int = 8) -> str:
    matched = match_intent_rules(intent, limit=limit)
    if not matched:
        return ""
    lines = [
        "Bundled FOFA library matches (use these query strings verbatim as precision strategies; do not invent app= names):"
    ]
    for rule in matched:
        lines.append(f'- {rule.name} [{rule.category}]: {rule.query}')
    return "\n".join(lines)


def search_rules(keyword: str = "", *, limit: int | None = None) -> list[FofaRule]:
    needle = keyword.strip().lower()
    if not needle:
        rules = list(LIBRARY_RULES)
        return rules if limit is None else rules[:limit]
    ranked: list[tuple[int, FofaRule]] = []
    for rule in LIBRARY_RULES:
        haystack = " ".join((rule.name, rule.query, rule.category, *rule.aliases)).lower()
        if needle not in haystack:
            continue
        score = 0
        if needle == rule.name.lower() or needle in {item.lower() for item in rule.aliases}:
            score = 0
        elif needle in rule.name.lower():
            score = 1
        else:
            score = 2
        ranked.append((score, rule))
    ranked.sort(key=lambda item: (item[0], item[1].name))
    matches = [rule for _, rule in ranked]
    return matches if limit is None else matches[:limit]


def resolve_rule_query(keyword: str) -> FofaRule:
    matches = search_rules(keyword, limit=20)
    exact = [
        rule
        for rule in matches
        if keyword.strip().lower() in {rule.name.lower(), *(item.lower() for item in rule.aliases)}
    ]
    chosen = exact[0] if len(exact) == 1 else (matches[0] if len(matches) == 1 else None)
    if chosen is None:
        names = "、".join(rule.name for rule in matches[:8]) or "无匹配"
        raise ValueError(f"规则库无法唯一匹配 {keyword!r}。候选：{names}。请用 `fofamap rules -k {keyword}` 查看。")
    return chosen


def rules_catalog(keyword: str = "") -> dict[str, Any]:
    rules = search_rules(keyword)
    grouped: dict[str, list[dict[str, str]]] = {}
    payload = []
    for rule in rules:
        item = {
            "name": rule.name,
            "query": rule.query,
            "category": rule.category,
            "aliases": ", ".join(rule.aliases),
        }
        grouped.setdefault(rule.category, []).append(item)
        payload.append(item)
    return {
        "source": "https://fofa.info/library",
        "note": "内置高价值子集，使用官方 app= 语法；完整规则仍以 FOFA 规则列表为准。",
        "total": len(LIBRARY_RULES),
        "count": len(rules),
        "categories": grouped,
        "rules": payload,
    }
