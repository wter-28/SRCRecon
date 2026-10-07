#include "core/DemoData.h"

#include <QDateTime>

namespace src {
namespace demo {

namespace {
const char *kIps[] = {"203.0.113.10",  "203.0.113.11", "203.0.113.24",
                      "198.51.100.7",  "198.51.100.33", "192.0.2.18",
                      "192.0.2.66"};

QString pickIp(int i) { return QString::fromLatin1(kIps[i % 7]); }
} // namespace

DomainAssetList subdomains(const QString &domain)
{
    static const char *prefixes[] = {
        "www", "api", "admin", "mail", "oa", "git", "test", "dev",
        "staging", "jenkins", "grafana", "portal", "vpn", "cdn", "static",
        "m", "pay", "sso", "monitor", "actuator"
    };
    DomainAssetList out;
    int i = 0;
    for (const char *p : prefixes) {
        DomainAsset d;
        d.host = QStringLiteral("%1.%2").arg(QString::fromLatin1(p), domain);
        d.ip = pickIp(i++);
        d.source = (i % 3 == 0) ? QStringLiteral("证书透明日志")
                                : QStringLiteral("字典爆破");
        out << d;
    }
    DomainAsset root;
    root.host = domain;
    root.ip = pickIp(0);
    root.source = QStringLiteral("主域名");
    out.prepend(root);
    return out;
}

WhoisInfo whois(const QString &domain)
{
    WhoisInfo w;
    w.domain = domain;
    w.registrar = QStringLiteral("示例注册商 Example Registrar, Inc.");
    w.registrant = QStringLiteral("示例科技有限公司");
    w.creationDate = QStringLiteral("2015-06-18T04:00:00Z");
    w.expiryDate = QStringLiteral("2027-06-18T04:00:00Z");
    w.updatedDate = QStringLiteral("2024-05-20T08:12:31Z");
    w.nameServers = QStringLiteral("ns1.example-dns.com, ns2.example-dns.com");
    w.status = QStringLiteral("clientTransferProhibited");
    w.raw = QStringLiteral("Domain Name: %1\nRegistrar: Example Registrar, Inc.\n"
                           "Creation Date: 2015-06-18\nRegistry Expiry Date: 2027-06-18\n"
                           "Name Server: NS1.EXAMPLE-DNS.COM\nStatus: clientTransferProhibited")
                .arg(domain);
    return w;
}

IcpInfo icp(const QString &domain)
{
    IcpInfo i;
    i.domain = domain;
    i.number = QStringLiteral("京ICP备15000000号-1");
    i.company = QStringLiteral("示例科技有限公司");
    i.nature = QStringLiteral("企业");
    i.siteName = QStringLiteral("示例官方网站");
    i.auditDate = QStringLiteral("2023-08-15");
    return i;
}

IpLocation ipLocation(const QString &ip)
{
    IpLocation l;
    l.ip = ip;
    l.country = QStringLiteral("中国");
    l.region = QStringLiteral("北京市");
    l.city = QStringLiteral("北京市");
    l.isp = QStringLiteral("示例云服务商");
    l.org = QStringLiteral("AS13335 Example Cloud LLC");
    l.asn = QStringLiteral("AS13335");
    l.timezone = QStringLiteral("Asia/Shanghai");
    return l;
}

PortResultList ports(const QString &host)
{
    struct P { int port; const char *svc; const char *banner; };
    static const P list[] = {
        {21,   "FTP",       "220 (vsFTPd 3.0.3)"},
        {22,   "SSH",       "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"},
        {80,   "HTTP",      "HTTP/1.1 200 OK Server: nginx/1.18.0"},
        {443,  "HTTPS",     "HTTP/1.1 200 OK Server: nginx/1.18.0"},
        {3306, "MySQL",     "5.7.38-log\x00"},
        {6379, "Redis",     "-ERR wrong number of arguments"},
        {8080, "HTTP-Alt",  "HTTP/1.1 200 OK Server: Apache-Coyote/1.1"},
        {9200, "Elasticsearch", "{\"name\":\"node-1\",\"version\":{\"number\":\"7.10.2\"}}"},
        {27017,"MongoDB",   "MongoDB"},
    };
    PortResultList out;
    for (const P &p : list) {
        PortResult r;
        r.host = host;
        r.port = p.port;
        r.service = QString::fromLatin1(p.svc);
        r.banner = QString::fromLatin1(p.banner);
        out << r;
    }
    return out;
}

WebFingerprintList fingerprints(const QString &baseUrl)
{
    WebFingerprintList out;

    WebFingerprint a;
    a.url = baseUrl;
    a.statusCode = 200;
    a.title = QStringLiteral("示例科技 - 首页");
    a.server = QStringLiteral("nginx/1.18.0");
    a.poweredBy = QStringLiteral("PHP/7.4.3");
    a.technologies = QStringLiteral("Nginx, PHP, jQuery, Bootstrap, WordPress");
    a.extraHeaders = QStringLiteral("x-powered-by: PHP/7.4.3; set-cookie: PHPSESSID, wordpress_test_cookie");
    out << a;

    WebFingerprint b;
    b.url = baseUrl + QStringLiteral("/api/");
    b.statusCode = 200;
    b.title = QStringLiteral("API 网关");
    b.server = QStringLiteral("openresty/1.21.4.1");
    b.poweredBy = QStringLiteral("Spring Boot");
    b.technologies = QStringLiteral("OpenResty, Java, Spring Boot, Swagger");
    b.extraHeaders = QStringLiteral("server: openresty; x-application-context: application");
    out << b;

    WebFingerprint c;
    c.url = baseUrl + QStringLiteral("/actuator");
    c.statusCode = 200;
    c.title = QString();
    c.server = QStringLiteral("nginx/1.18.0");
    c.poweredBy = QString();
    c.technologies = QStringLiteral("Spring Boot Actuator");
    c.extraHeaders = QStringLiteral("content-type: application/vnd.spring-boot.actuator.v3+json");
    out << c;

    return out;
}

DirRecordList dirs(const QString &baseUrl)
{
    struct D { const char *path; int code; qint64 len; const char *type; const char *note; };
    static const D list[] = {
        {"/robots.txt",         200, 128,   "text/plain",       "成功"},
        {"/.git/config",        200, 262,   "text/plain",       "源码泄露"},
        {"/.env",               200, 512,   "text/plain",       "配置泄露"},
        {"/actuator/env",       200, 4096,  "application/json", "敏感接口"},
        {"/swagger-ui.html",    200, 1024,  "text/html",        "API文档"},
        {"/admin/",             302, 0,     "text/html",        "跳转"},
        {"/backup.zip",         200, 1048576, "application/zip", "备份文件"},
        {"/phpinfo.php",        200, 8192,  "text/html",        "信息泄露"},
        {"/druid/index.html",   200, 2048,  "text/html",        "监控面板"},
        {"/server-status",      403, 163,   "text/html",        "禁止访问"},
    };
    DirRecordList out;
    for (const D &d : list) {
        DirRecord r;
        r.url = baseUrl + QString::fromLatin1(d.path);
        r.statusCode = d.code;
        r.length = d.len;
        r.contentType = QString::fromLatin1(d.type);
        r.note = QString::fromLatin1(d.note);
        out << r;
    }
    return out;
}

UrlRecordList urls(const QString &baseUrl)
{
    struct U { const char *path; int code; const char *type; qint64 len; const char *src; };
    static const U list[] = {
        {"/",                200, "text/html",        18432, "爬虫页面"},
        {"/index.php",       200, "text/html",        18432, "爬虫页面"},
        {"/about.html",      200, "text/html",        9216,  "爬虫页面"},
        {"/news/",           200, "text/html",        12288, "爬虫页面"},
        {"/js/app.js",       200, "application/javascript", 154321, "JS文件"},
        {"/js/vendor.js",    200, "application/javascript", 402144, "JS文件"},
        {"/css/main.css",    200, "text/css",         20112, "爬虫页面"},
        {"/api/user/list",   401, "application/json", 96,    "接口"},
        {"/login",           200, "text/html",        4096,  "表单"},
        {"/uploads/1.png",   200, "image/png",        65412, "爬虫页面"},
        {"https://cdn.example-external.com/lib.js", 200, "application/javascript", 88213, "站外JS"},
    };
    UrlRecordList out;
    for (const U &u : list) {
        UrlRecord r;
        const QString p = QString::fromLatin1(u.path);
        r.url = p.startsWith(QStringLiteral("http")) ? p : baseUrl + p;
        r.statusCode = u.code;
        r.contentType = QString::fromLatin1(u.type);
        r.length = u.len;
        r.source = QString::fromLatin1(u.src);
        out << r;
    }
    return out;
}

} // namespace demo
} // namespace src
