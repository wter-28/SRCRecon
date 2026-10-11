#include "modules/CdnModule.h"

#include <QFutureSynchronizer>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QJsonValue>
#include <QMutex>
#include <QMutexLocker>
#include <QSet>
#include <QStringList>
#include <QThreadPool>
#include <QtConcurrent/QtConcurrentRun>

#include <atomic>

#include "core/CdnDetect.h"
#include "core/CdnIpRange.h"
#include "core/DemoData.h"
#include "core/NetUtil.h"
#include "core/ReconState.h"

namespace src {

namespace {

/// 从响应头中提取标题（用于源站探测证据）
QString quickTitle(const QByteArray &body)
{
    const QString h = QString::fromUtf8(body.left(64 * 1024));
    const int a = h.indexOf(QStringLiteral("<title"), 0, Qt::CaseInsensitive);
    if (a < 0)
        return QString();
    const int s = h.indexOf(QLatin1Char('>'), a);
    const int e = h.indexOf(QStringLiteral("</title>"), s, Qt::CaseInsensitive);
    if (s < 0 || e < 0)
        return QString();
    return h.mid(s + 1, e - s - 1).simplified().left(80);
}

/// 通过 DoH（Google DNS JSON 接口）解析主机的 A 记录，用于发现常见源站子域名。
/// 失败时返回空列表，保证调用方可优雅降级、不阻塞、不崩溃。
QStringList dohResolveA(const QString &host, int timeoutMs)
{
    QStringList ips;
    if (host.isEmpty())
        return ips;

    static const QString kDoh =
        QStringLiteral("https://dns.google/resolve?name=%1&type=A");
    const QString url = kDoh.arg(NetUtil::urlEncode(host.trimmed().toLower()));
    const HttpResponse res = NetUtil::httpRequest(url, qMax(4000, timeoutMs));
    if (!res.ok)
        return ips;

    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(res.body, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject())
        return ips;

    const QJsonArray answers = doc.object().value(QStringLiteral("Answer")).toArray();
    for (const QJsonValue &v : answers)
    {
        const QJsonObject o = v.toObject();
        if (o.value(QStringLiteral("type")).toInt() != 1)  // 1 = A 记录
            continue;
        const QString data = o.value(QStringLiteral("data")).toString().trimmed();
        if (!data.isEmpty() && !ips.contains(data))
            ips << data;
    }
    return ips;
}

/// 计算 CDN / WAF 边缘判定的置信度（0-100）。
/// 依据：CNAME 厂商匹配、响应头命中、WAF 特征、边缘 IP 是否落在已知 CDN 网段。
int edgeConfidence(bool cnameMatch, bool headerHit, bool wafHit,
                   bool ipInRange, bool ipKnown)
{
    int c = 0;
    if (cnameMatch) c += 30;
    if (headerHit)  c += 35;
    if (wafHit)     c += 15;
    if (ipInRange)  c += 30;

    // 有 CDN 迹象但解析 IP 落在非 CDN 网段：可能是误判或已回源，降低置信度
    if (ipKnown && !ipInRange && (cnameMatch || headerHit))
        c -= 20;

    return qBound(0, c, 100);
}

} // namespace

void CdnModule::run(ModuleContext &ctx)
{
    const EngineOptions &o = *ctx.opt;

    if (o.demo)
    {
        ctx.info(QStringLiteral("演示模式：返回内置 CDN 数据"));
        CdnRecord r;
        r.host     = o.host.isEmpty() ? QStringLiteral("example.com") : o.host;
        r.ip       = QStringLiteral("104.16.0.1");
        r.category = QStringLiteral("CDN");
        r.vendor   = QStringLiteral("Cloudflare（演示）");
        r.cname    = QStringLiteral("example.com.cdn.cloudflare.net");
        r.reason   = QStringLiteral("响应头 cf-ray（演示数据）");
        r.confidence = 100;
        CdnRecordList list;
        list << r;
        ctx.progress(1, 1);
        ctx.addCdn(list);
        ctx.ok(QStringLiteral("CDN 识别完成（演示数据）"));
        return;
    }

    if (!ctx.state)
    {
        ctx.warn(QStringLiteral("缺少共享状态，跳过 CDN 识别"));
        return;
    }

    // 汇总待检测主机：共享状态中的主机（含根目标）+ 兜底根目标
    QStringList hosts;
    for (const auto &h : ctx.state->hosts())
        hosts << h.host;
    if (!o.host.isEmpty() && !hosts.contains(o.host))
        hosts.prepend(o.host);
    if (hosts.isEmpty())
    {
        ctx.warn(QStringLiteral("无可检测主机，跳过 CDN 识别"));
        return;
    }

    const int cap = qMax(1, o.maxScanHosts);
    QStringList limited = hosts;
    if (limited.size() > cap)
        limited = limited.mid(0, cap);

    ctx.info(QStringLiteral("开始 CDN / WAF 识别，待检测主机 %1 个（上限 %2）")
                 .arg(hosts.size())
                 .arg(cap));

    std::atomic<int> done{0};
    QMutex mtx;
    CdnRecordList records;
    const int total = limited.size();

    QFutureSynchronizer<void> sync;
    for (const QString &host : limited)
    {
        sync.addFuture(QtConcurrent::run(ctx.pool, [&, host]() {
            if (ctx.isCancelled())
                return;

            // 1) CNAME 链（DoH）
            const QStringList chain = cdn::lookupCnameChain(host, o.timeoutMs);
            QString vendor = cdn::matchCnameVendor(chain);

            // 2) 响应头探测
            QString probeUrl = QStringLiteral("http://") + host;
            if (!o.baseUrl.isEmpty() && host == o.host)
                probeUrl = o.baseUrl;
            const HttpResponse res = NetUtil::httpRequest(probeUrl, o.timeoutMs);

            const cdn::Verdict hv = cdn::detectByHeaders(res);
            if (vendor.isEmpty() && hv.hit)
                vendor = hv.vendor;
            const QString waf = cdn::detectWaf(res);

            QStringList reasons;
            if (!chain.isEmpty())
                reasons << QStringLiteral("CNAME 链 %1").arg(chain.join(QStringLiteral(" -> ")));
            if (!hv.reason.isEmpty())
                reasons << hv.reason;
            if (!waf.isEmpty())
                reasons << QStringLiteral("WAF 特征 %1").arg(waf);

            // 3) 边缘 IP 网段核验：落入已知 CDN 网段是强证据
            const QString edgeIp = NetUtil::resolveFirst(host);
            QString rangeVendor;
            const bool ipInRange =
                !edgeIp.isEmpty() && cdn::matchCdnRange(edgeIp, &rangeVendor);
            const bool ipKnown = !edgeIp.isEmpty();

            // 网段证据可补充/纠正厂商（仅在原有厂商缺失或为通用时）
            if (ipInRange
                && (vendor.isEmpty() || vendor.startsWith(QStringLiteral("通用"))))
                vendor = rangeVendor;

            const bool hit = !vendor.isEmpty() || hv.hit || !waf.isEmpty();
            if (hit)
            {
                if (ipInRange)
                    reasons << QStringLiteral("边缘 IP 位于 %1 网段").arg(rangeVendor);

                CdnRecord r;
                r.host     = host;
                r.ip       = edgeIp;
                r.category = hv.hit || !vendor.isEmpty()
                                 ? (waf.isEmpty() ? QStringLiteral("CDN")
                                                  : QStringLiteral("云 WAF"))
                                 : QStringLiteral("WAF");
                r.vendor   = vendor.isEmpty() ? waf : vendor;
                r.cname    = chain.join(QStringLiteral(", "));
                r.reason   = cdn::joinReason(reasons);
                r.confidence = edgeConfidence(!vendor.isEmpty(), hv.hit,
                                              !waf.isEmpty(), ipInRange, ipKnown);

                QMutexLocker locker(&mtx);
                records << r;
            }

            // 4) 标记状态，供端口扫描跳过
            ctx.state->setCdn(host, hit, vendor.isEmpty() ? waf : vendor, chain);

            const int d = ++done;
            if (d % 5 == 0 || d == total)
                ctx.progress(d, total);
        }));
    }
    sync.waitForFinished();

    if (ctx.isCancelled())
    {
        ctx.warn(QStringLiteral("CDN 识别已被取消"));
        return;
    }

    // 5) 源站候选探测：对未被判定为 CDN 的 IP，用 Host 头直连（http/https）试探；
    //    并额外通过 DoH 解析常见源站子域名，扩大命中率。
    if (!records.isEmpty())
    {
        QSet<QString> edgeIps;
        for (const CdnRecord &r : records)
        {
            if (!r.ip.isEmpty())
                edgeIps.insert(r.ip);
        }

        // 抓取一次边缘页面，用于与源站候选的标题 / 特征比对
        QString edgeTitle;
        QString edgeServer;
        {
            const QString edgeUrl = !o.baseUrl.isEmpty()
                                        ? o.baseUrl
                                        : QStringLiteral("http://") + o.host;
            const HttpResponse er = NetUtil::httpRequest(edgeUrl, o.timeoutMs);
            edgeTitle  = quickTitle(er.body);
            edgeServer = er.header(QStringLiteral("server"));
        }

        // 汇总候选 IP：共享状态中的非边缘 IP + 常见源站子域名解析结果
        QStringList candidates;
        for (const QString &ip : ctx.state->allIps())
        {
            if (edgeIps.contains(ip) || ctx.state->isCdnIp(ip))
                continue;
            if (!candidates.contains(ip))
                candidates << ip;
        }
        if (!o.host.isEmpty())
        {
            const QStringList guesses = {
                QStringLiteral("direct.")  + o.host,
                QStringLiteral("origin.")  + o.host,
                QStringLiteral("dev.")     + o.host,
                QStringLiteral("origin-")  + o.host};
            for (const QString &g : guesses)
            {
                for (const QString &ip : dohResolveA(g, o.timeoutMs))
                {
                    if (edgeIps.contains(ip) || candidates.contains(ip))
                        continue;
                    candidates << ip;
                }
            }
        }

        int probed = 0;
        for (const QString &ip : candidates)
        {
            if (probed >= 40)
                break;
            ++probed;

            const QMap<QString, QString> hdrs = {{QStringLiteral("Host"),
                                                  o.host.isEmpty() ? ip : o.host}};
            // 先试 http，失败再试 https；均携带目标 Host 头
            HttpResponse pr =
                NetUtil::httpRequest(QStringLiteral("http://") + ip + QLatin1Char('/'),
                                     o.timeoutMs, QStringLiteral("GET"), QByteArray(), hdrs);
            QString scheme = QStringLiteral("http");
            if (pr.statusCode <= 0)
            {
                pr = NetUtil::httpRequest(QStringLiteral("https://") + ip + QLatin1Char('/'),
                                          o.timeoutMs, QStringLiteral("GET"), QByteArray(), hdrs);
                scheme = QStringLiteral("https");
            }
            if (pr.statusCode <= 0)
                continue;

            const QString title  = quickTitle(pr.body);
            const QString server = pr.header(QStringLiteral("server"));

            int conf = 40;
            QStringList evParts;
            evParts << QStringLiteral("%1 直连返回 %2").arg(scheme).arg(pr.statusCode);
            if (!title.isEmpty())
            {
                evParts << QStringLiteral("标题「%1」").arg(title);
                if (!edgeTitle.isEmpty()
                    && title.compare(edgeTitle, Qt::CaseInsensitive) == 0)
                {
                    conf += 40;
                    evParts << QStringLiteral("标题与边缘页面一致");
                }
            }
            else
            {
                conf -= 10;
            }
            if (!edgeServer.isEmpty() && !server.isEmpty()
                && server.compare(edgeServer, Qt::CaseInsensitive) == 0)
            {
                conf += 10;
                evParts << QStringLiteral("Server 与边缘一致");
            }
            conf = qBound(0, conf, 100);

            const QString ev = evParts.join(QStringLiteral("；"));
            ctx.state->addOriginCandidate(ip, ev);

            CdnRecord orr;
            orr.host       = o.host;
            orr.ip         = ip;
            orr.category   = QStringLiteral("源站候选");
            orr.realIp     = ip;
            orr.confidence = conf;
            orr.reason     = ev;
            QMutexLocker locker(&mtx);
            records << orr;
        }
    }

    ctx.addCdn(records);
    ctx.ok(QStringLiteral("CDN / WAF 识别完成，命中 %1 个目标").arg(records.size()));
}

CdnRecordList CdnModule::buildAggregation(ReconState &state)
{
    CdnRecordList out;
    for (const QString &ip : state.allIps())
    {
        const QStringList vhosts = state.hostsOfIp(ip);
        if (vhosts.isEmpty())
            continue;

        QString vendor;
        const bool cdn = state.isCdnIp(ip, &vendor);

        const QVector<int> ports = state.portsOf(ip);
        QStringList portStrs;
        for (int p : ports)
            portStrs << QString::number(p);

        CdnRecord r;
        r.host     = vhosts.first();
        r.ip       = ip;
        r.category = cdn ? QStringLiteral("资产聚合/CDN") : QStringLiteral("资产聚合");
        r.vendor   = cdn ? vendor : QStringLiteral("-");

        // 聚合行置信度：CDN 行的置信度取决于 IP 是否落在已知 CDN 网段
        if (cdn)
        {
            QString rangeVendor;
            r.confidence = cdn::matchCdnRange(ip, &rangeVendor) ? 85 : 60;
        }
        else
        {
            r.confidence = 30;
        }

        QStringList parts;
        parts << QStringLiteral("虚拟主机 %1 个：%2").arg(vhosts.size()).arg(vhosts.join(QStringLiteral(", ")));
        if (!ports.isEmpty())
            parts << QStringLiteral("开放端口：%1").arg(portStrs.join(QStringLiteral(",")));
        r.reason = parts.join(QStringLiteral("；"));

        out << r;
    }
    return out;
}

} // namespace src