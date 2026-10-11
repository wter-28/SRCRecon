#include "modules/PortScanModule.h"

#include <QFutureSynchronizer>
#include <QMutex>
#include <QMutexLocker>
#include <QSet>
#include <QStringList>
#include <QThreadPool>
#include <QtConcurrent/QtConcurrentRun>

#include <algorithm>
#include <atomic>

#include "core/DemoData.h"
#include "core/NetUtil.h"
#include "core/Wordlists.h"

namespace src {

namespace {

/// 需要发送 HTTP 探测的端口
bool isHttpPort(int port)
{
    static const QSet<int> set = {80, 81, 82, 83, 84, 85, 88, 8000, 8001, 8008, 8080,
                                  8081, 8082, 8083, 8088, 8090, 8091, 8161, 8180, 8888,
                                  8983, 9000, 9090, 9200, 10000, 15672, 50070};
    return set.contains(port);
}

/// 是否为 TLS / HTTPS 端口
bool isTlsPort(int port)
{
    static const QSet<int> set = {443, 4443, 8443, 9443};
    return set.contains(port);
}

/// 是否为可继续访问的 Web 端口（用于串联指纹/目录/爬虫）
bool isWebPort(int port)
{
    return isHttpPort(port) || isTlsPort(port);
}

/// 依据 Banner 内容修正服务识别结果
QString guessService(int port, const QString &banner)
{
    const QString b = banner.toLower();
    if (b.startsWith(QStringLiteral("ssh-")))
        return QStringLiteral("SSH");
    if (b.contains(QStringLiteral("http/1.")) || b.contains(QStringLiteral("server:")))
        return QStringLiteral("HTTP");
    if (b.contains(QStringLiteral("-err")) && b.contains(QStringLiteral("wrong number")))
        return QStringLiteral("Redis");
    if (b.contains(QStringLiteral("mysql")))
        return QStringLiteral("MySQL");
    if (b.contains(QStringLiteral("mongodb")))
        return QStringLiteral("MongoDB");
    if (b.startsWith(QStringLiteral("220")) && b.contains(QStringLiteral("ftp")))
        return QStringLiteral("FTP");
    if (b.contains(QStringLiteral("\"cluster_name\"")) || b.contains(QStringLiteral("elasticsearch")))
        return QStringLiteral("Elasticsearch");
    if (b.contains(QStringLiteral("smbd")) || b.contains(QStringLiteral("samba")))
        return QStringLiteral("SMB");
    return words::serviceByPort(port);
}

} // namespace

QVector<int> PortScanModule::parsePortSpec(const QString &spec)
{
    QString s = spec.trimmed();
    if (s.isEmpty() || s.compare(QStringLiteral("common"), Qt::CaseInsensitive) == 0)
        return words::commonPorts();

    QVector<int> ports;
    const QStringList parts = s.split(QLatin1Char(','), Qt::SkipEmptyParts);
    for (const QString &p0 : parts) {
        const QString p = p0.trimmed();
        if (p.isEmpty())
            continue;

        const int dash = p.indexOf(QLatin1Char('-'));
        if (dash > 0) {
            bool ok1 = false, ok2 = false;
            const int a = p.left(dash).trimmed().toInt(&ok1);
            const int b = p.mid(dash + 1).trimmed().toInt(&ok2);
            if (!ok1 || !ok2)
                continue;
            for (int i = qMax(1, qMin(a, b)); i <= qMin(65535, qMax(a, b)); ++i)
                ports << i;
        } else {
            bool ok = false;
            const int v = p.toInt(&ok);
            if (ok && v > 0 && v <= 65535)
                ports << v;
        }
    }

    // 去重并保持顺序
    QVector<int> out;
    QSet<int> seen;
    for (int p : ports) {
        if (!seen.contains(p)) {
            seen.insert(p);
            out << p;
        }
    }
    return out;
}

void PortScanModule::run(ModuleContext &ctx)
{
    const EngineOptions &o = *ctx.opt;

    if (o.demo) {
        ctx.info(QStringLiteral("演示模式：返回内置端口数据"));
        const PortResultList list = demo::ports(o.host.isEmpty() ? QStringLiteral("example.com")
                                                                 : o.host);
        ctx.progress(60, 100);
        ctx.addPorts(list);
        ctx.progress(100, 100);
        ctx.ok(QStringLiteral("发现 %1 个开放端口（演示数据）").arg(list.size()));
        return;
    }

    if (o.host.isEmpty()) {
        ctx.error(QStringLiteral("扫描目标为空，跳过端口扫描"));
        return;
    }

    const QVector<int> ports = parsePortSpec(o.portSpec);
    if (ports.isEmpty())
    {
        ctx.error(QStringLiteral("端口范围解析为空：%1").arg(o.portSpec));
        return;
    }

    // 按 IP 聚合扫描目标：同一 IP 只扫一次，避免对共享主机的重复扫描
    struct Target
    {
        QString     ip;
        QStringList vhosts;
    };
    QVector<Target> targets;
    QSet<QString>   seenIps;
    QSet<QString>   cdnSkipped;

    if (ctx.state)
    {
        for (const QString &ip : ctx.state->allIps())
        {
            if (ip.isEmpty() || seenIps.contains(ip))
                continue;
            seenIps.insert(ip);

            if (ctx.state->isCdnIp(ip))
            {
                cdnSkipped.insert(ip);
                continue;  // CDN 边缘 IP 跳过端口扫描，避免无意义请求与风控
            }

            Target t;
            t.ip     = ip;
            t.vhosts = ctx.state->hostsOfIp(ip);
            targets << t;
        }
    }

    // 兜底：共享状态不可用时仅扫描根目标
    if (targets.isEmpty() && !o.host.isEmpty())
    {
        Target t;
        t.ip     = o.isIp ? o.host : NetUtil::resolveFirst(o.host);
        t.vhosts = {o.host};
        if (!t.ip.isEmpty())
            targets << t;
    }

    if (!cdnSkipped.isEmpty())
        ctx.warn(QStringLiteral("跳过 %1 个 CDN 边缘 IP 的端口扫描（详见 CDN 标签页）")
                     .arg(cdnSkipped.size()));

    if (targets.isEmpty())
    {
        ctx.warn(QStringLiteral("无可用扫描目标，跳过端口扫描"));
        return;
    }

    const int cap = qMax(1, o.maxScanHosts);
    if (targets.size() > cap)
    {
        ctx.warn(QStringLiteral("扫描目标 %1 个，超出上限 %2，仅扫描前 %2 个")
                     .arg(targets.size()).arg(cap));
        targets = targets.mid(0, cap);
    }

    const int connectTimeout = qBound(300, o.timeoutMs, 3000);
    const int total = targets.size() * ports.size();
    ctx.info(QStringLiteral("待扫描独立 IP %1 个，端口 %2 个，共 %3 次探测，连接超时 %4 ms")
                 .arg(targets.size())
                 .arg(ports.size())
                 .arg(total)
                 .arg(connectTimeout));

    auto pickHost = [](const QStringList &vhosts, const QString &ip) -> QString {
        for (const QString &h : vhosts)
        {
            if (!h.isEmpty() && h != ip)
                return h;
        }
        return ip;
    };
    auto webUrl = [](const QString &scheme, const QString &host, int port) -> QString {
        if ((scheme == QLatin1String("http") && port == 80)
            || (scheme == QLatin1String("https") && port == 443))
            return scheme + QStringLiteral("://") + host;
        return scheme + QStringLiteral("://") + host + QLatin1Char(':') + QString::number(port);
    };

    std::atomic<int> done{0};
    QMutex mtx;
    PortResultList open;

    QFutureSynchronizer<void> sync;
    for (const Target &t : targets)
    {
        for (int port : ports)
        {
            sync.addFuture(QtConcurrent::run(ctx.pool, [&, t, port]() {
                if (ctx.isCancelled())
                    return;

                const QString hostName = pickHost(t.vhosts, t.ip);
                QString banner;
                const QByteArray probe = isHttpPort(port)
                                             ? QByteArray("HEAD / HTTP/1.0\r\nHost: ")
                                                   + hostName.toUtf8() + QByteArray("\r\n\r\n")
                                             : QByteArray();

                if (NetUtil::tcpConnect(t.ip, port, connectTimeout, &banner, probe))
                {
                    PortResult r;
                    r.host    = hostName;
                    r.port    = port;
                    r.service = guessService(port, banner);
                    r.banner  = banner;

                    QMutexLocker locker(&mtx);
                    open.append(r);

                    if (ctx.state)
                    {
                        ctx.state->addPort(t.ip, port);

                        // 串联：把探测到的 Web 服务登记为后续指纹/目录/爬虫的目标
                        if (isWebPort(port))
                        {
                            const QString scheme = isTlsPort(port) ? QStringLiteral("https")
                                                                   : QStringLiteral("http");
                            int added = 0;
                            for (const QString &vh : t.vhosts)
                            {
                                if (added >= 3)
                                    break;
                                ctx.state->addWebTarget(webUrl(scheme, vh, port));
                                ++added;
                            }
                        }
                    }
                }

                const int d = ++done;
                if (d % 40 == 0 || d == total)
                    ctx.progress(d, total);
            }));
        }
    }
    sync.waitForFinished();

    if (ctx.isCancelled())
    {
        ctx.warn(QStringLiteral("端口扫描已被取消"));
        return;
    }

    std::sort(open.begin(), open.end(), [](const PortResult &a, const PortResult &b) {
        if (a.host != b.host)
            return a.host < b.host;
        return a.port < b.port;
    });

    ctx.addPorts(open);
    ctx.ok(QStringLiteral("端口扫描完成，开放端口 %1 个").arg(open.size()));
}

} // namespace src
