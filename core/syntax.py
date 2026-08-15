"""Official FOFA query syntax, aligned with https://fofa.info/api/introd."""

from __future__ import annotations

from typing import Any

# Operators documented on the FOFA API query appendix.
OPERATORS = [
    {"op": "=", "meaning": "匹配（包含）"},
    {"op": "==", "meaning": "完全匹配，通常更快"},
    {"op": "!=", "meaning": "不匹配"},
    {"op": "&&", "meaning": "与"},
    {"op": "||", "meaning": "或"},
    {"op": "*=", "meaning": "模糊匹配（部分字段）"},
    {"op": "()", "meaning": "括号分组"},
]

# Query-side fields from the official syntax appendix. These are used in qbase64,
# and are not all valid as /search/all return `fields`.
QUERY_FIELDS: list[dict[str, str]] = [
    {"field": "app", "example": 'app="ThinkPHP"', "meaning": "FOFA 规则库应用名，见 https://fofa.info/library"},
    {"field": "fid", "example": 'fid="sSXXGNUO2FefBTcCLIT/2Q=="', "meaning": "FOFA 聚合站点指纹 ID"},
    {"field": "product", "example": 'product="NGINX"', "meaning": "FOFA 标记的产品名"},
    {"field": "category", "example": 'category="服务"', "meaning": "FOFA 标记的产品分类"},
    {"field": "type", "example": 'type="subdomain"', "meaning": "资产类型：service 协议资产 / subdomain 网站资产"},
    {"field": "cloud_name", "example": 'cloud_name="Aliyun"', "meaning": "云服务商"},
    {"field": "is_cloud", "example": "is_cloud=true", "meaning": "是否云上资产"},
    {"field": "is_fraud", "example": "is_fraud=false", "meaning": "是否仿冒资产（会员）"},
    {"field": "is_honeypot", "example": "is_honeypot=false", "meaning": "是否蜜罐（会员）"},
    {"field": "is_ipv6", "example": "is_ipv6=true", "meaning": "是否 IPv6 资产"},
    {"field": "is_domain", "example": "is_domain=true", "meaning": "是否域名资产"},
    {"field": "ip", "example": 'ip="1.1.1.1"', "meaning": "IPv4/IPv6，支持 C 段如 1.1.1.0/24"},
    {"field": "port", "example": 'port="6379"', "meaning": "端口"},
    {"field": "host", "example": 'host="fofa.info"', "meaning": "主机名 / URL"},
    {"field": "domain", "example": 'domain="qq.com"', "meaning": "根域名"},
    {"field": "domain", "example": 'domain=="qq.com"', "meaning": "根域名完全匹配"},
    {"field": "title", "example": 'title="powered by"', "meaning": "网站标题"},
    {"field": "header", "example": 'header="elastic"', "meaning": "HTTP 响应头"},
    {"field": "header_hash", "example": 'header_hash="1258854265"', "meaning": "HTTP 响应头哈希"},
    {"field": "body", "example": 'body="网络空间测绘"', "meaning": "HTML 正文"},
    {"field": "body_hash", "example": 'body_hash="-2090962452"', "meaning": "HTML 正文哈希"},
    {"field": "js_name", "example": 'js_name="js/jquery.js"', "meaning": "页面引用的 JS 文件名"},
    {"field": "js_md5", "example": 'js_md5="82ac3f14327a8b7ba49baa208d4eaa15"', "meaning": "JS 源码 MD5"},
    {"field": "icon_hash", "example": 'icon_hash="-247388890"', "meaning": "网站图标 MurmurHash3，可用 -ico 计算"},
    {"field": "status_code", "example": 'status_code="200"', "meaning": "HTTP 状态码（查询语法，不是默认返回字段）"},
    {"field": "protocol", "example": 'protocol="https"', "meaning": "协议"},
    {"field": "base_protocol", "example": 'base_protocol="udp"', "meaning": "基础协议 tcp/udp"},
    {"field": "banner", "example": 'banner="users" && protocol="ftp"', "meaning": "服务 Banner"},
    {"field": "os", "example": 'os="centos"', "meaning": "操作系统"},
    {"field": "server", "example": 'server=="Microsoft-IIS/10"', "meaning": "Server 头 / 服务软件"},
    {"field": "country", "example": 'country="CN"', "meaning": "国家代码"},
    {"field": "region", "example": 'region="Zhejiang"', "meaning": "省份 / 地区"},
    {"field": "city", "example": 'city="Hangzhou"', "meaning": "城市"},
    {"field": "asn", "example": 'asn="13649"', "meaning": "ASN 号"},
    {"field": "org", "example": 'org="Amazon.com, Inc."', "meaning": "ASN 组织"},
    {"field": "icp", "example": 'icp="京ICP证030173号"', "meaning": "网站 ICP 备案号"},
    {"field": "cert", "example": 'cert="baidu"', "meaning": "证书全文"},
    {"field": "cert.subject.cn", "example": 'cert.subject.cn="baidu.com"', "meaning": "证书使用者 CN"},
    {"field": "cert.subject.org", "example": 'cert.subject.org="Beijing Baidu"', "meaning": "证书使用者组织"},
    {"field": "cert.issuer.org", "example": 'cert.issuer.org="DigiCert"', "meaning": "证书颁发者组织"},
    {"field": "cert.is_valid", "example": "cert.is_valid=true", "meaning": "证书是否有效（会员）"},
    {"field": "cert.is_match", "example": "cert.is_match=true", "meaning": "证书域名是否匹配资产"},
    {"field": "cert.is_equal", "example": "cert.is_equal=true", "meaning": "证书颁发者与使用者是否相同"},
    {"field": "tls.ja3s", "example": 'tls.ja3s="..."', "meaning": "JA3S 指纹"},
    {"field": "jarm", "example": 'jarm="..."', "meaning": "JARM 指纹"},
    {"field": "cname", "example": 'cname="cdn.example.com"', "meaning": "CNAME 记录"},
    {"field": "cname_domain", "example": 'cname_domain="example.com"', "meaning": "CNAME 解析出的主域"},
    {"field": "port_size", "example": 'port_size="6"', "meaning": "开放端口数量（会员）"},
    {"field": "ip_ports", "example": 'ip_ports="80,161"', "meaning": "同一 IP 同时开放的端口"},
    {"field": "after", "example": 'after="2024-01-01"', "meaning": "资产更新时间晚于"},
    {"field": "before", "example": 'before="2024-12-31"', "meaning": "资产更新时间早于"},
]


def syntax_catalog() -> dict[str, Any]:
    return {
        "source": "https://fofa.info/api/introd",
        "library": "https://fofa.info/library",
        "operators": OPERATORS,
        "query_fields": QUERY_FIELDS,
        "notes": [
            "查询语句需 UTF-8 后做标准 Base64，作为 qbase64 参数提交。",
            "app= 对应规则列表中的应用名；fid= 对应规则指纹 ID。",
            "status_code / is_honeypot 等是查询语法，不一定能作为 /search/all 的返回字段。",
            "连续翻页请用 /api/v1/search/next 的 next 游标，不要用深层 page。",
        ],
    }
