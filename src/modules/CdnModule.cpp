#include "modules/CdnModule.h"

#include <QFutureSynchronizer>
#include <QMutex>
#include <QMutexLocker>
#include <QSet>
#include <QStringList>
#include <QThreadPool>
#include <QtConcurrent/QtConcurrentRun>

#include <atomic>

#include "core/CdnDetect.h"
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

            const bool hit = !vendor.isEmpty() || hv.hit || !waf.isEmpty();
            if (hit)
            {
                CdnRecord r;
                r.host     = host;
                r.ip       = NetUtil::resolveFirst(host);
                r.category = hv.hit || !vendor.isEmpty()
                                 ? (waf.isEmpty() ? QStringLiteral("CDN")
                                                  : QStringLiteral("云 WAF"))
                                 : QStringLiteral("WAF");
                r.vendor   = vendor.isEmpty() ? waf : vendor;
                r.cname    = chain.join(QStringLiteral(", "));
                r.reason   = cdn::joinReason(reasons);

                QMutexLocker locker(&mtx);
                records << r;
            }

            // 3) 标记状态，供端口扫描跳过
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

    // 4) 源站候选探测：对未被判定为 CDN 的 IP，用 Host 头直连试探
    if (!records.isEmpty())
    {
        QSet<QString> edgeIps;
        for (const CdnRecord &r : records)
        {
            if (!r.ip.isEmpty())
                edgeIps.insert(r.ip);
        }

        int probed = 0;
        for (const QString &ip : ctx.state->allIps())
        {
            if (probed >= 30)
                break;
            if (edgeIps.contains(ip) || ctx.state->isCdnIp(ip))
                continue;

            ++probed;
            const QMap<QString, QString> hdrs = {{QStringLiteral("Host"),
                                                  o.host.isEmpty() ? ip : o.host}};
            const HttpResponse pr =
                NetUtil::httpRequest(QStringLiteral("http://") + ip + QLatin1Char('/'),
                                     o.timeoutMs, QStringLiteral("GET"), QByteArray(), hdrs);
            if (pr.statusCode <= 0)
                continue;

            const QString title = quickTitle(pr.body);
            QString ev = QStringLiteral("直连返回 %1").arg(pr.statusCode);
            if (!title.isEmpty())
                ev += QStringLiteral("，标题「%1」").arg(title);

            ctx.state->addOriginCandidate(ip, ev);

            CdnRecord orr;
            orr.host     = o.host;
            orr.ip       = ip;
            orr.category = QStringLiteral("源站候选");
            orr.realIp   = ip;
            orr.reason   = ev;
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