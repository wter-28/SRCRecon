#include "core/CdnDetect.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QJsonValue>
#include <QMap>
#include <QPair>
#include <QRegularExpression>
#include <QVector>

namespace src {
namespace cdn {

namespace {

// ---------------- CDN CNAME 后缀签名 ----------------
// 命中后缀即判定为对应厂商（小写匹配）
const QVector<QPair<QString, QString>> &cnameSuffixTable()
{
    static const QVector<QPair<QString, QString>> t = {
        {QStringLiteral("cdn.cloudflare.net"),   QStringLiteral("Cloudflare")},
        {QStringLiteral("cloudflare.net"),       QStringLiteral("Cloudflare")},
        {QStringLiteral("cloudflare.com"),       QStringLiteral("Cloudflare")},
        {QStringLiteral("akamaiedge.net"),       QStringLiteral("Akamai")},
        {QStringLiteral("akamaitechnologies.com"), QStringLiteral("Akamai")},
        {QStringLiteral("edgekey.net"),          QStringLiteral("Akamai")},
        {QStringLiteral("edgesuite.net"),        QStringLiteral("Akamai")},
        {QStringLiteral("akamai.net"),           QStringLiteral("Akamai")},
        {QStringLiteral("edgecastcdn.net"),      QStringLiteral("EdgeCast")},
        {QStringLiteral("fastly.net"),           QStringLiteral("Fastly")},
        {QStringLiteral("fastlylb.net"),         QStringLiteral("Fastly")},
        {QStringLiteral("cloudfront.net"),       QStringLiteral("AWS CloudFront")},
        {QStringLiteral("azureedge.net"),        QStringLiteral("Azure CDN")},
        {QStringLiteral("azurefd.net"),          QStringLiteral("Azure Front Door")},
        {QStringLiteral("trafficmanager.net"),   QStringLiteral("Azure Traffic Manager")},
        {QStringLiteral("vo.llnwd.net"),         QStringLiteral("Limelight")},
        {QStringLiteral("llnwd.net"),            QStringLiteral("Limelight")},
        {QStringLiteral("kunlungr.com"),         QStringLiteral("阿里云 CDN")},
        {QStringLiteral("alikunlun.com"),        QStringLiteral("阿里云 CDN")},
        {QStringLiteral("alikunlun.net"),        QStringLiteral("阿里云 CDN")},
        {QStringLiteral("cdngslb.com"),          QStringLiteral("阿里云 CDN")},
        {QStringLiteral("alicdn.com"),           QStringLiteral("阿里云 CDN")},
        {QStringLiteral("dnsv1.com"),            QStringLiteral("腾讯云 CDN")},
        {QStringLiteral("txcdn.com"),            QStringLiteral("腾讯云 CDN")},
        {QStringLiteral("tcdns.com"),            QStringLiteral("腾讯云 CDN")},
        {QStringLiteral("wsdvs.com"),            QStringLiteral("网宿 CDN")},
        {QStringLiteral("wscloudcdn.com"),       QStringLiteral("网宿 CDN")},
        {QStringLiteral("chinacache.com"),       QStringLiteral("蓝汛 CDN")},
        {QStringLiteral("chinacache.net"),       QStringLiteral("蓝汛 CDN")},
        {QStringLiteral("ccgslb.com"),           QStringLiteral("蓝汛 CDN")},
        {QStringLiteral("qiniudns.com"),         QStringLiteral("七牛 CDN")},
        {QStringLiteral("incapdns.net"),         QStringLiteral("Imperva Incapsula")},
        {QStringLiteral("impervadns.net"),       QStringLiteral("Imperva")},
        {QStringLiteral("hwcdn.net"),            QStringLiteral("Highwinds")},
        {QStringLiteral("stackpathdns.com"),     QStringLiteral("StackPath")},
        {QStringLiteral("stackpathcdn.com"),     QStringLiteral("StackPath")},
        {QStringLiteral("cdn77.org"),            QStringLiteral("CDN77")},
        {QStringLiteral("b-cdn.net"),            QStringLiteral("BunnyCDN")},
        {QStringLiteral("kcdn.net"),             QStringLiteral("KeyCDN")},
        {QStringLiteral("cachefly.net"),         QStringLiteral("CacheFly")},
        {QStringLiteral("sucuri.net"),           QStringLiteral("Sucuri")},
        {QStringLiteral("gslb"),                 QStringLiteral("通用 GSLB/CDN")}
    };
    return t;
}

// ---------------- CDN 响应头签名 ----------------
struct HeaderSig
{
    QString header;    // 头名（小写）
    QString contains;  // 头值需包含的片段（空 = 只要存在该头即命中）
    QString vendor;
};

const QVector<HeaderSig> &cdnHeaderTable()
{
    static const QVector<HeaderSig> t = {
        {QStringLiteral("cf-ray"),              QString(), QStringLiteral("Cloudflare")},
        {QStringLiteral("cf-cache-status"),     QString(), QStringLiteral("Cloudflare")},
        {QStringLiteral("x-amz-cf-id"),         QString(), QStringLiteral("AWS CloudFront")},
        {QStringLiteral("x-amz-cf-pop"),        QString(), QStringLiteral("AWS CloudFront")},
        {QStringLiteral("x-azure-ref"),         QString(), QStringLiteral("Azure Front Door")},
        {QStringLiteral("x-msedge-ref"),        QString(), QStringLiteral("Azure CDN")},
        {QStringLiteral("x-fastly-request-id"), QString(), QStringLiteral("Fastly")},
        {QStringLiteral("x-served-by"),         QStringLiteral("cache"), QStringLiteral("Fastly")},
        {QStringLiteral("x-akamai-request-id"), QString(), QStringLiteral("Akamai")},
        {QStringLiteral("akamai-grn"),          QString(), QStringLiteral("Akamai")},
        {QStringLiteral("x-sucuri-id"),         QString(), QStringLiteral("Sucuri")},
        {QStringLiteral("x-sucuri-cache"),      QString(), QStringLiteral("Sucuri")},
        {QStringLiteral("ali-swift-global-savetime"), QString(), QStringLiteral("阿里云 CDN")},
        {QStringLiteral("eagleid"),             QString(), QStringLiteral("阿里云 CDN")},
        {QStringLiteral("timing-allow-origin"), QStringLiteral("ali"), QStringLiteral("阿里云 CDN")},
        {QStringLiteral("cdn-cache"),           QStringLiteral("hit"), QStringLiteral("腾讯云 CDN")},
        {QStringLiteral("x-cache"),             QStringLiteral("cloudfront"),
                                               QStringLiteral("AWS CloudFront")},
        {QStringLiteral("x-cache"),             QStringLiteral("akamai"), QStringLiteral("Akamai")},
        {QStringLiteral("server"),              QStringLiteral("cloudflare"),
                                               QStringLiteral("Cloudflare")},
        {QStringLiteral("server"),              QStringLiteral("akamaighost"),
                                               QStringLiteral("Akamai")},
        {QStringLiteral("server"),              QStringLiteral("cloudfront"),
                                               QStringLiteral("AWS CloudFront")},
        {QStringLiteral("server"),              QStringLiteral("alicdn"), QStringLiteral("阿里云 CDN")},
        {QStringLiteral("server"),              QStringLiteral("cdn"), QStringLiteral("通用 CDN")},
        {QStringLiteral("via"),                 QStringLiteral("cache"), QStringLiteral("通用 CDN")}
    };
    return t;
}

// ---------------- WAF 签名 ----------------
struct WafSig
{
    QString header;    // 头名（小写）
    QString contains;  // 头值需包含的片段（空 = 只要存在即命中）
    QString vendor;
};

const QVector<WafSig> &wafTable()
{
    static const QVector<WafSig> t = {
        {QStringLiteral("cf-ray"),              QString(), QStringLiteral("Cloudflare WAF")},
        {QStringLiteral("x-sucuri-id"),         QString(), QStringLiteral("Sucuri WAF")},
        {QStringLiteral("x-protected-by"),      QString(), QStringLiteral("通用 WAF")},
        {QStringLiteral("x-waf"),               QString(), QStringLiteral("通用 WAF")},
        {QStringLiteral("x-denied-reason"),     QString(), QStringLiteral("通用 WAF")},
        {QStringLiteral("wzws-ray"),            QString(), QStringLiteral("360 网站卫士")},
        {QStringLiteral("server"),              QStringLiteral("cloudflare"),
                                               QStringLiteral("Cloudflare WAF")},
        {QStringLiteral("server"),              QStringLiteral("akamaighost"),
                                               QStringLiteral("Akamai WAF")},
        {QStringLiteral("server"),              QStringLiteral("yunjiasu"),
                                               QStringLiteral("百度云加速")},
        {QStringLiteral("server"),              QStringLiteral("bigip"), QStringLiteral("F5 BIG-IP")},
        {QStringLiteral("server"),              QStringLiteral("modsecurity"),
                                               QStringLiteral("ModSecurity")},
        {QStringLiteral("server"),              QStringLiteral("safe3waf"), QStringLiteral("Safe3WAF")},
        {QStringLiteral("server"),              QStringLiteral("360wzws"), QStringLiteral("360 网站卫士")},
        {QStringLiteral("server"),              QStringLiteral("yunsuo"), QStringLiteral("云锁")},
        {QStringLiteral("server"),              QStringLiteral("tengine"), QStringLiteral("Tengine/阿里云盾")}
    };
    return t;
}

// 命中 cookie 名称即判定
const QVector<QPair<QString, QString>> &wafCookieTable()
{
    static const QVector<QPair<QString, QString>> t = {
        {QStringLiteral("acw_tc"),      QStringLiteral("阿里云盾 WAF")},
        {QStringLiteral("aliyungf_tc"), QStringLiteral("阿里云盾 WAF")},
        {QStringLiteral("yunsuo_session"), QStringLiteral("云锁")},
        {QStringLiteral("waf_cookie"),  QStringLiteral("通用 WAF")},
        {QStringLiteral("incap_ses"),   QStringLiteral("Imperva Incapsula")},
        {QStringLiteral("visid_incap"), QStringLiteral("Imperva Incapsula")}
    };
    return t;
}

// ---------------- 版本 / 漏洞线索 ----------------
struct VulnMarker
{
    QString marker;  // 在技术栈字符串中匹配的关键字（小写）
    QString hint;    // 线索文本
};

const QVector<VulnMarker> &vulnTable()
{
    static const QVector<VulnMarker> t = {
        {QStringLiteral("weblogic"),
         QStringLiteral("WebLogic：关注 CVE-2020-14882/14883 未授权 RCE、CVE-2019-2725 反序列化")},
        {QStringLiteral("struts")  , QStringLiteral("Struts2：关注 S2-045/S2-057 远程代码执行")},
        {QStringLiteral("spring")  , QStringLiteral("Spring：若 actuator 未授权，关注 CVE-2022-22965 与内存/环境泄露")},
        {QStringLiteral("thinkphp"), QStringLiteral("ThinkPHP：关注 5.x 远程代码执行与多语言本地包含")},
        {QStringLiteral("shiro")   , QStringLiteral("Apache Shiro：关注 rememberMe 反序列化（CVE-2016-4437 及其绕过）")},
        {QStringLiteral("dedecms") , QStringLiteral("DedeCMS：关注后台弱口令、任意文件上传/包含及历史变量覆盖漏洞")},
        {QStringLiteral("discuz")  , QStringLiteral("Discuz：关注后台 Getshell、UC_KEY 泄露与 SSRF")},
        {QStringLiteral("jenkins") , QStringLiteral("Jenkins：关注未授权脚本控制台与 CVE-2024-23897 任意文件读取")},
        {QStringLiteral("tomcat")  , QStringLiteral("Tomcat：关注 CVE-2017-12615 PUT 上传、AJP Ghostcat（CVE-2020-1938）")},
        {QStringLiteral("php")     , QStringLiteral("PHP：确认版本并核对已知漏洞，注意 phpinfo/备份文件泄露")}
    };
    return t;
}

} // namespace

QString joinReason(const QStringList &parts)
{
    QStringList cleaned;
    for (const QString &p : parts)
    {
        if (!p.isEmpty() && !cleaned.contains(p))
            cleaned << p;
    }
    return cleaned.join(QStringLiteral("；"));
}

QStringList lookupCnameChain(const QString &host, int timeoutMs)
{
    QStringList chain;
    if (host.isEmpty())
        return chain;

    static const QString kDoh =
        QStringLiteral("https://dns.google/resolve?name=%1&type=CNAME");

    QString current = host.trimmed().toLower();
    for (int hop = 0; hop < 5; ++hop)
    {
        const QString url = kDoh.arg(NetUtil::urlEncode(current));
        const HttpResponse res = NetUtil::httpRequest(url, qMax(4000, timeoutMs));
        if (!res.ok)
            break;

        QJsonParseError err{};
        const QJsonDocument doc = QJsonDocument::fromJson(res.body, &err);
        if (err.error != QJsonParseError::NoError || !doc.isObject())
            break;

        const QJsonArray answers = doc.object().value(QStringLiteral("Answer")).toArray();
        QString next;
        for (const QJsonValue &v : answers)
        {
            const QJsonObject o = v.toObject();
            if (o.value(QStringLiteral("type")).toInt() != 5)  // 5 = CNAME
                continue;
            QString data = o.value(QStringLiteral("data")).toString().trimmed().toLower();
            if (data.endsWith(QLatin1Char('.')))
                data.chop(1);
            if (!data.isEmpty())
            {
                next = data;
                break;
            }
        }

        if (next.isEmpty() || chain.contains(next))
            break;
        chain << next;
        current = next;
    }
    return chain;
}

QString matchCnameVendor(const QStringList &chain)
{
    for (const QString &cname : chain)
    {
        for (const auto &p : cnameSuffixTable())
        {
            if (cname == p.first || cname.endsWith(QLatin1Char('.') + p.first))
                return p.second;
        }
    }
    return QString();
}

Verdict detectByHeaders(const HttpResponse &res)
{
    Verdict v;
    if (!res.ok && res.headers.isEmpty())
        return v;

    QStringList reasons;
    for (const HeaderSig &s : cdnHeaderTable())
    {
        const QString val = res.header(s.header);
        if (val.isEmpty())
            continue;
        if (!s.contains.isEmpty()
            && !val.toLower().contains(s.contains.toLower()))
            continue;

        v.hit = true;
        if (v.vendor.isEmpty() || v.vendor.startsWith(QStringLiteral("通用")))
            v.vendor = s.vendor;
        reasons << QStringLiteral("响应头 %1").arg(s.header);
    }

    if (v.hit)
    {
        v.category = QStringLiteral("CDN");
        v.reason = joinReason(reasons);
    }
    return v;
}

QString detectWaf(const HttpResponse &res)
{
    for (const WafSig &s : wafTable())
    {
        const QString val = res.header(s.header);
        if (val.isEmpty())
            continue;
        if (!s.contains.isEmpty()
            && !val.toLower().contains(s.contains.toLower()))
            continue;
        return s.vendor;
    }

    const QString cookies = res.header(QStringLiteral("set-cookie")).toLower();
    if (!cookies.isEmpty())
    {
        for (const auto &p : wafCookieTable())
        {
            if (cookies.contains(p.first))
                return p.second;
        }
    }
    return QString();
}

QString cveHints(const QString &techJoined, const QByteArray &body)
{
    const QString tech = techJoined.toLower();
    QStringList hints;

    for (const VulnMarker &m : vulnTable())
    {
        if (tech.contains(m.marker) && !hints.contains(m.hint))
            hints << m.hint;
    }

    // jQuery 版本 -> 已知 XSS 线索
    static const QRegularExpression jqRe(
        QStringLiteral("jquery[.-]?(\\d+\\.\\d+\\.\\d+)"),
        QRegularExpression::CaseInsensitiveOption);
    const QRegularExpressionMatch jm = jqRe.match(tech);
    if (jm.hasMatch())
    {
        const QString ver = jm.captured(1);
        const int major = ver.section(QLatin1Char('.'), 0, 0).toInt();
        const int minor = ver.section(QLatin1Char('.'), 1, 1).toInt();
        if (major < 3 || (major == 3 && minor < 5))
            hints << QStringLiteral("jQuery %1 较旧，关注 CVE-2020-11022/11023 XSS（升级至 3.5.0+）").arg(ver);
    }

    Q_UNUSED(body);
    return hints.join(QStringLiteral("\n"));
}

} // namespace cdn
} // namespace src