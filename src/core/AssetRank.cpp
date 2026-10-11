#include "core/AssetRank.h"

#include <QSet>
#include <QStringList>
#include <QUrl>

#include <algorithm>

namespace src {

namespace {

/// 从 URL 中解析主机名（失败返回空）
QString hostOfUrl(const QString &url)
{
    if (url.isEmpty())
        return QString();

    QUrl u(url);
    if (!u.isValid() || u.host().isEmpty())
    {
        // 兼容无协议头的裸地址
        QUrl u2(QStringLiteral("http://") + url);
        return u2.host();
    }
    return u.host();
}

/// 拼接证据字段，忽略空串
QString joinEvidence(const QStringList &parts)
{
    QStringList out;
    for (const QString &p : parts)
    {
        if (!p.trimmed().isEmpty())
            out << p.trimmed();
    }
    return out.join(QStringLiteral("；"));
}

} // namespace

QString AssetRank::severityOf(const DirRecord &r)
{
    const QString n = r.note;
    if (n.contains(QStringLiteral("源码")) || n.contains(QStringLiteral("配置"))
        || n.contains(QStringLiteral("备份")))
        return QStringLiteral("高");
    if (n.contains(QStringLiteral("敏感")) || n.contains(QStringLiteral("泄露"))
        || n.contains(QStringLiteral("管理")) || n.contains(QStringLiteral("监控"))
        || n.contains(QStringLiteral("文档")))
        return QStringLiteral("中");
    if (n.contains(QStringLiteral("禁止")) || n.contains(QStringLiteral("认证"))
        || n.contains(QStringLiteral("文件目录")) || n.contains(QStringLiteral("跳转")))
        return QStringLiteral("低");
    return QStringLiteral("信息");
}

QString AssetRank::severityOf(const WebFingerprint &f)
{
    if (!f.vulnHint.isEmpty())
        return QStringLiteral("高");
    if (f.statusCode >= 500)
        return QStringLiteral("低");
    return QStringLiteral("信息");
}

QString AssetRank::severityOf(const ApiEndpoint &e)
{
    if (!e.severity.isEmpty())
        return e.severity;

    const QString n = e.note;
    if (n.contains(QStringLiteral("敏感")) || n.contains(QStringLiteral("配置"))
        || n.contains(QStringLiteral("未授权")))
        return QStringLiteral("高");
    if (n.contains(QStringLiteral("清单")) || n.contains(QStringLiteral("信息泄露")))
        return QStringLiteral("中");
    if (n.contains(QStringLiteral("可访问")))
        return QStringLiteral("低");
    return QStringLiteral("信息");
}

QString AssetRank::severityOf(const PortResult &p)
{
    // 常见未授权 / 数据类服务，暴露风险最高
    static const QSet<int> high = {2375, 2379, 2380, 6379, 9200, 11211, 27017, 9042};
    // 数据库 / 远程管理 / 文件共享，风险中等
    static const QSet<int> mid  = {21, 22, 23, 445, 1433, 1521, 3306, 5432, 5900, 5984, 3389};
    // 其余非 Web 服务，风险较低
    static const QSet<int> low  = {25, 110, 135, 139, 873, 1080, 8161, 8888, 15672, 50070};

    if (high.contains(p.port))
        return QStringLiteral("高");
    if (mid.contains(p.port))
        return QStringLiteral("中");
    if (low.contains(p.port))
        return QStringLiteral("低");
    return QStringLiteral("信息");
}

int AssetRank::scoreOf(const QString &severity, const QString &category)
{
    int base;
    if (severity == QStringLiteral("高"))
        base = 90;
    else if (severity == QStringLiteral("中"))
        base = 60;
    else if (severity == QStringLiteral("低"))
        base = 30;
    else
        base = 5;

    int bonus = 0;
    if (category == QStringLiteral("CDN源站"))
        bonus = 15;
    else if (category == QStringLiteral("接口"))
        bonus = 10;
    else if (category == QStringLiteral("敏感路径"))
        bonus = 10;
    else if (category == QStringLiteral("端口"))
        bonus = 5;
    else if (category == QStringLiteral("Web指纹"))
        bonus = 5;

    return base + bonus;
}

AssetSummaryList AssetRank::build(const ReconState &state, const PortResultList &ports,
                                  const WebFingerprintList &fps, const DirRecordList &dirs,
                                  const ApiEndpointList &eps, const CdnRecordList &cdn)
{
    AssetSummaryList out;
    QSet<QString> seen;

    // 去重：同一 (ip|host, 类别, 值) 只保留首次出现
    auto push = [&out, &seen](const AssetSummary &s) {
        if (s.value.isEmpty())
            return;
        const QString key = s.ip + QLatin1Char('|') + s.host + QLatin1Char('|')
                            + s.category + QLatin1Char('|') + s.value;
        if (seen.contains(key))
            return;
        seen.insert(key);
        out << s;
    };

    // 1) 开放端口
    for (const PortResult &p : ports)
    {
        AssetSummary s;
        s.host     = p.host;
        s.ip       = state.ipOfHost(p.host);
        s.category = QStringLiteral("端口");
        s.value    = QStringLiteral("%1:%2").arg(p.host).arg(p.port);
        s.source   = QStringLiteral("端口扫描");
        s.severity = severityOf(p);
        s.score    = scoreOf(s.severity, s.category);
        s.evidence = joinEvidence({p.service, p.banner.left(120)});
        push(s);
    }

    // 2) Web 指纹
    for (const WebFingerprint &f : fps)
    {
        const QString host = hostOfUrl(f.url);
        AssetSummary s;
        s.host     = host;
        s.ip       = state.ipOfHost(host);
        s.category = QStringLiteral("Web指纹");
        s.value    = f.url;
        s.source   = QStringLiteral("Web指纹");
        s.severity = severityOf(f);
        s.score    = scoreOf(s.severity, s.category);
        s.evidence = joinEvidence({f.title, f.server, f.waf,
                                   f.vulnHint.isEmpty()
                                       ? QString()
                                       : QStringLiteral("漏洞线索：%1").arg(f.vulnHint)});
        push(s);
    }

    // 3) 敏感路径 / 目录
    for (const DirRecord &d : dirs)
    {
        const QString host = hostOfUrl(d.url);
        AssetSummary s;
        s.host     = host;
        s.ip       = state.ipOfHost(host);
        s.category = QStringLiteral("敏感路径");
        s.value    = d.url;
        s.source   = QStringLiteral("目录探测");
        s.severity = severityOf(d);
        s.score    = scoreOf(s.severity, s.category);
        s.evidence = joinEvidence({QString::number(d.statusCode), d.note});
        push(s);
    }

    // 4) 接口 / 暴露面
    for (const ApiEndpoint &e : eps)
    {
        const QString host = hostOfUrl(e.url);
        AssetSummary s;
        s.host     = host;
        s.ip       = state.ipOfHost(host);
        s.category = QStringLiteral("接口");
        s.value    = e.url;
        s.source   = e.source.isEmpty() ? QStringLiteral("接口") : e.source;
        s.severity = severityOf(e);
        s.score    = scoreOf(s.severity, s.category);
        s.evidence = joinEvidence({e.method, e.note, e.params});
        push(s);
    }

    // 5) CDN / 源站 / IP 聚合记录
    for (const CdnRecord &c : cdn)
    {
        AssetSummary s;
        s.host = c.host;
        s.ip   = c.ip;
        if (c.category.contains(QStringLiteral("源站")))
        {
            s.category = QStringLiteral("CDN源站");
            s.value    = c.realIp.isEmpty() ? c.ip : c.realIp;
            s.source   = QStringLiteral("源站探测");
            s.severity = QStringLiteral("中");
        }
        else if (c.category.contains(QStringLiteral("资产聚合")))
        {
            s.category = QStringLiteral("IP资产");
            s.value    = c.ip.isEmpty() ? c.host : c.ip;
            s.source   = QStringLiteral("资产聚合");
            s.severity = QStringLiteral("信息");
        }
        else
        {
            s.category = QStringLiteral("CDN");
            s.value    = c.vendor.isEmpty() ? c.ip : c.vendor;
            s.source   = QStringLiteral("CDN识别");
            s.severity = QStringLiteral("信息");
        }
        s.score    = scoreOf(s.severity, s.category);
        s.evidence = c.reason;
        push(s);
    }

    // 6) 兜底：为每个已解析 IP 生成资产行（CDN 模块关闭时同样有数据）
    for (const QString &ip : state.allIps())
    {
        const QStringList vhosts = state.hostsOfIp(ip);
        if (vhosts.isEmpty())
            continue;

        AssetSummary s;
        s.host     = vhosts.first();
        s.ip       = ip;
        s.category = QStringLiteral("IP资产");
        s.value    = ip;
        s.source   = QStringLiteral("资产聚合");
        s.severity = QStringLiteral("信息");
        s.score    = scoreOf(s.severity, s.category);
        s.evidence = QStringLiteral("绑定主机 %1 个：%2")
                         .arg(vhosts.size())
                         .arg(vhosts.join(QStringLiteral(", ")));
        push(s);
    }

    // 评分降序；评分相同时按级别 / 类别 / 值排序，保证输出稳定
    std::sort(out.begin(), out.end(), [](const AssetSummary &a, const AssetSummary &b) {
        if (a.score != b.score)
            return a.score > b.score;
        if (a.severity != b.severity)
            return a.severity < b.severity;
        if (a.category != b.category)
            return a.category < b.category;
        return a.value < b.value;
    });

    return out;
}

} // namespace src