#include "modules/AssetInfoModule.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QJsonValue>
#include <QMap>
#include <QVariant>

#include "core/DemoData.h"
#include "core/NetUtil.h"

namespace src {

namespace {

const QString kDemoIp = QStringLiteral("203.0.113.10");

/// 解析 whois 原始文本，字段名做归一化（去空格、转小写）后匹配
void parseWhois(const QString &raw, WhoisInfo &info)
{
    QMap<QString, QString> kv;
    QStringList nsList;
    QStringList statusList;

    const QStringList lines = raw.split(QLatin1Char('\n'));
    for (const QString &line0 : lines) {
        const QString line = line0.trimmed();
        const int c = line.indexOf(QLatin1Char(':'));
        if (c <= 0)
            continue;

        QString key = line.left(c).trimmed().toLower();
        key.remove(QLatin1Char(' '));
        const QString val = line.mid(c + 1).trimmed();
        if (val.isEmpty())
            continue;

        if (key == QLatin1String("nameserver")) {
            if (!nsList.contains(val))
                nsList << val;
            continue;
        }
        if (key == QLatin1String("domainstatus")) {
            if (!statusList.contains(val))
                statusList << val;
            continue;
        }
        if (!kv.contains(key))
            kv.insert(key, val);
    }

    auto get = [&kv](const QStringList &keys) -> QString {
        for (const QString &k : keys) {
            if (kv.contains(k))
                return kv.value(k);
        }
        return QString();
    };

    info.registrar  = get({QStringLiteral("registrar"), QStringLiteral("sponsoringregistrar")});
    info.registrant = get({QStringLiteral("registrantorganization"), QStringLiteral("registrant"),
                           QStringLiteral("registrantname"), QStringLiteral("registrantorg")});
    info.creationDate = get({QStringLiteral("creationdate"), QStringLiteral("registeredon"),
                             QStringLiteral("registrationtime"),
                             QStringLiteral("domainregistrationdate")});
    info.expiryDate = get({QStringLiteral("registryexpirydate"), QStringLiteral("expirationtime"),
                           QStringLiteral("expirydate"), QStringLiteral("expirationdate")});
    info.updatedDate = get({QStringLiteral("updateddate"), QStringLiteral("lastupdated"),
                            QStringLiteral("modifieddate")});
    info.nameServers = nsList.join(QStringLiteral(", "));
    info.status      = statusList.join(QStringLiteral(", "));
    info.raw         = raw.left(4096);
}

/// 递归展开 JSON，便于兼容不同备案接口的字段命名
void flattenJson(const QJsonValue &v, QMap<QString, QString> &out)
{
    if (v.isObject()) {
        const QJsonObject obj = v.toObject();
        for (auto it = obj.begin(); it != obj.end(); ++it) {
            if (it.value().isString() || it.value().isDouble() || it.value().isBool())
                out.insert(it.key().toLower(), it.value().toVariant().toString());
            else
                flattenJson(it.value(), out);
        }
    } else if (v.isArray()) {
        const QJsonArray arr = v.toArray();
        for (const QJsonValue &x : arr)
            flattenJson(x, out);
    }
}

QString pickField(const QMap<QString, QString> &m, const QStringList &keys)
{
    for (const QString &k : keys) {
        const QString v = m.value(k.toLower());
        if (!v.isEmpty())
            return v;
    }
    return QString();
}

} // namespace

void AssetInfoModule::run(ModuleContext &ctx)
{
    const EngineOptions &o = *ctx.opt;
    const int totalSteps = 3;

    if (o.demo) {
        ctx.info(QStringLiteral("演示模式：返回内置资产信息"));
        ctx.addWhois(demo::whois(o.host.isEmpty() ? QStringLiteral("example.com") : o.host));
        ctx.progress(1, totalSteps);
        ctx.addIcp(demo::icp(o.host.isEmpty() ? QStringLiteral("example.com") : o.host));
        ctx.progress(2, totalSteps);
        ctx.addIpLocation(demo::ipLocation(kDemoIp));
        ctx.progress(totalSteps, totalSteps);
        ctx.ok(QStringLiteral("资产信息收集完成（演示数据）"));
        return;
    }

    // ---- Whois ----
    if (o.isIp || o.host.isEmpty()) {
        ctx.warn(QStringLiteral("目标非域名，跳过 Whois 查询"));
    } else {
        ctx.info(QStringLiteral("Whois 查询：%1").arg(o.host));
        const QString server = NetUtil::whoisServerFor(o.host);
        const QString raw = NetUtil::whoisQuery(server, o.host, qMax(8000, o.timeoutMs));
        if (raw.trimmed().isEmpty()) {
            ctx.warn(QStringLiteral("Whois 服务器 %1 无响应").arg(server));
        } else if (raw.contains(QStringLiteral("No match"), Qt::CaseInsensitive)
                   || raw.contains(QStringLiteral("NOT FOUND"), Qt::CaseInsensitive)) {
            ctx.warn(QStringLiteral("Whois 未查询到该域名注册信息"));
        } else {
            WhoisInfo info;
            info.domain = o.host;
            parseWhois(raw, info);
            ctx.addWhois(info);
            ctx.ok(QStringLiteral("Whois 查询完成（注册商：%1）")
                       .arg(info.registrar.isEmpty() ? QStringLiteral("未知") : info.registrar));
        }
    }
    ctx.progress(1, totalSteps);
    if (ctx.isCancelled())
        return;

    // ---- ICP 备案 ----
    if (o.isIp || o.host.isEmpty()) {
        ctx.warn(QStringLiteral("目标非域名，跳过 ICP 备案查询"));
    } else if (o.icpApiUrl.trimmed().isEmpty()) {
        ctx.warn(QStringLiteral("未配置 ICP 备案查询接口，跳过"));
    } else {
        QString url = o.icpApiUrl;
        url.replace(QStringLiteral("{domain}"), o.host);
        ctx.info(QStringLiteral("查询 ICP 备案：%1").arg(url));
        const HttpResponse res = NetUtil::httpRequest(url, qMax(8000, o.timeoutMs));
        if (!res.ok) {
            ctx.warn(QStringLiteral("备案接口请求失败：%1").arg(res.errorString));
        } else {
            QJsonParseError err{};
            const QJsonDocument doc = QJsonDocument::fromJson(res.body, &err);
            if (err.error != QJsonParseError::NoError) {
                ctx.warn(QStringLiteral("备案接口返回内容无法解析"));
            } else {
                QMap<QString, QString> flat;
                flattenJson(doc.isArray() ? QJsonValue(doc.array()) : QJsonValue(doc.object()), flat);

                IcpInfo info;
                info.domain = o.host;
                info.number = pickField(flat, {QStringLiteral("icp"), QStringLiteral("icpnumber"),
                                               QStringLiteral("icpno"), QStringLiteral("beian"),
                                               QStringLiteral("number"), QStringLiteral("code")});
                info.company = pickField(flat, {QStringLiteral("unitname"), QStringLiteral("company"),
                                                QStringLiteral("companyname"),
                                                QStringLiteral("unit"), QStringLiteral("zhusu")});
                info.nature = pickField(flat, {QStringLiteral("naturename"), QStringLiteral("nature"),
                                               QStringLiteral("unittype")});
                info.siteName = pickField(flat, {QStringLiteral("sitename"), QStringLiteral("webname"),
                                                 QStringLiteral("domain")});
                info.auditDate = pickField(flat, {QStringLiteral("audittime"),
                                                  QStringLiteral("auditdate"),
                                                  QStringLiteral("updatetime"),
                                                  QStringLiteral("time")});

                if (info.number.isEmpty() && info.company.isEmpty())
                    ctx.warn(QStringLiteral("备案接口未返回有效数据"));
                else {
                    ctx.addIcp(info);
                    ctx.ok(QStringLiteral("ICP 备案：%1 / %2").arg(info.number, info.company));
                }
            }
        }
    }
    ctx.progress(2, totalSteps);
    if (ctx.isCancelled())
        return;

    // ---- IP 归属地 ----
    QString ip = o.host;
    if (!o.isIp) {
        ctx.info(QStringLiteral("解析域名 IP：%1").arg(o.host));
        ip = NetUtil::resolveFirst(o.host);
    }
    if (ip.isEmpty()) {
        ctx.warn(QStringLiteral("未能解析到 IP，跳过归属地查询"));
    } else {
        const QString url = QStringLiteral(
            "http://ip-api.com/json/%1?lang=zh-CN&fields=status,message,country,regionName,city,"
            "isp,org,as,timezone,query").arg(ip);
        ctx.info(QStringLiteral("查询 IP 归属地：%1").arg(ip));
        const HttpResponse res = NetUtil::httpRequest(url, qMax(6000, o.timeoutMs));
        if (!res.ok) {
            ctx.warn(QStringLiteral("IP 归属地接口请求失败：%1").arg(res.errorString));
        } else {
            QJsonParseError err{};
            const QJsonObject obj = QJsonDocument::fromJson(res.body, &err).object();
            if (err.error != QJsonParseError::NoError || obj.value(QStringLiteral("status")).toString()
                    != QLatin1String("success")) {
                ctx.warn(QStringLiteral("IP 归属地查询无结果：%1")
                             .arg(obj.value(QStringLiteral("message")).toString()));
            } else {
                IpLocation loc;
                loc.ip      = obj.value(QStringLiteral("query")).toString(ip);
                loc.country = obj.value(QStringLiteral("country")).toString();
                loc.region  = obj.value(QStringLiteral("regionName")).toString();
                loc.city    = obj.value(QStringLiteral("city")).toString();
                loc.isp     = obj.value(QStringLiteral("isp")).toString();
                loc.org     = obj.value(QStringLiteral("org")).toString();
                loc.asn     = obj.value(QStringLiteral("as")).toString();
                loc.timezone = obj.value(QStringLiteral("timezone")).toString();
                ctx.addIpLocation(loc);
                ctx.ok(QStringLiteral("IP 归属地：%1 %2 %3 / %4")
                           .arg(loc.country, loc.region, loc.city, loc.isp));
            }
        }
    }
    ctx.progress(totalSteps, totalSteps);
}

} // namespace src
