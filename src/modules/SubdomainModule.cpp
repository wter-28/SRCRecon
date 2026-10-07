#include "modules/SubdomainModule.h"

#include <QMutex>
#include <QMutexLocker>
#include <QFutureSynchronizer>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QRandomGenerator>
#include <QThreadPool>
#include <QtConcurrent/QtConcurrentRun>

#include <atomic>

#include "core/DemoData.h"
#include "core/NetUtil.h"
#include "core/Wordlists.h"

namespace src {

namespace {

/// 演示模式下模拟进度推进
void demoProgress(ModuleContext &ctx, int total)
{
    const int step = qMax(1, total / 10);
    for (int i = 0; i <= total; i += step)
        ctx.progress(qMin(i, total), total);
    ctx.progress(total, total);
}

/// 通过 crt.sh 证书透明日志获取域名相关主机名
QStringList fetchCtLog(const QString &domain, int timeoutMs, ModuleContext &ctx)
{
    QStringList hosts;
    const QString url = QStringLiteral("https://crt.sh/?q=%25.") + domain
                      + QStringLiteral("&output=json");

    ctx.info(QStringLiteral("查询证书透明日志 crt.sh ..."));
    const HttpResponse res = NetUtil::httpRequest(url, qMax(15000, timeoutMs * 3));
    if (!res.ok) {
        ctx.warn(QStringLiteral("证书透明日志查询失败：%1").arg(res.errorString));
        return hosts;
    }

    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(res.body, &err);
    if (err.error != QJsonParseError::NoError || !doc.isArray()) {
        ctx.warn(QStringLiteral("证书透明日志返回内容无法解析"));
        return hosts;
    }

    const QJsonArray arr = doc.array();
    for (const QJsonValue &v : arr) {
        const QString names = v.toObject().value(QStringLiteral("name_value")).toString();
        const QStringList parts = names.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
        for (QString n : parts) {
            n = n.trimmed().toLower();
            if (n.startsWith(QStringLiteral("*.")))
                n = n.mid(2);
            if (n.isEmpty() || n.contains(QLatin1Char(' ')) || n.contains(QLatin1Char('*')))
                continue;
            if (n == domain || n.endsWith(QLatin1Char('.') + domain))
                hosts << n;
        }
    }
    hosts.removeDuplicates();
    ctx.ok(QStringLiteral("证书透明日志获取到 %1 个主机名").arg(hosts.size()));
    return hosts;
}

} // namespace

void SubdomainModule::run(ModuleContext &ctx)
{
    const EngineOptions &o = *ctx.opt;

    if (o.demo) {
        ctx.info(QStringLiteral("演示模式：使用内置子域名数据"));
        const QString domain = o.host.isEmpty() ? QStringLiteral("example.com") : o.host;
        const DomainAssetList list = demo::subdomains(domain);
        demoProgress(ctx, list.size());
        ctx.addSubdomains(list);
        ctx.ok(QStringLiteral("发现 %1 个子域名（演示数据）").arg(list.size()));
        return;
    }

    if (o.isIp) {
        ctx.warn(QStringLiteral("目标为 IP 地址，跳过子域名枚举"));
        return;
    }
    if (o.host.isEmpty()) {
        ctx.error(QStringLiteral("目标域名为空，跳过子域名枚举"));
        return;
    }

    const QString root = o.host;

    // 1) 汇总候选主机名
    QMap<QString, QString> candidates;  // host -> 来源
    candidates.insert(root, QStringLiteral("主域名"));

    const QStringList dict = words::loadWordlist(o.subdomainWordlist, words::subdomains());
    ctx.info(QStringLiteral("子域名字典条目：%1").arg(dict.size()));
    for (const QString &w : dict) {
        if (candidates.size() >= o.subdomainMax)
            break;
        const QString h = w + QLatin1Char('.') + root;
        if (!candidates.contains(h))
            candidates.insert(h, QStringLiteral("字典爆破"));
    }

    const QStringList ctHosts = fetchCtLog(root, o.timeoutMs, ctx);
    for (const QString &h : ctHosts) {
        if (candidates.size() >= o.subdomainMax)
            break;
        if (!candidates.contains(h))
            candidates.insert(h, QStringLiteral("证书透明日志"));

        // 证书日志里的多级域名，其父级一并纳入
        int idx = h.indexOf(QLatin1Char('.'));
        while (idx > 0) {
            const QString parent = h.mid(idx + 1);
            if (parent == root)
                break;
            if (parent.endsWith(QLatin1Char('.') + root) && !candidates.contains(parent))
                candidates.insert(parent, QStringLiteral("证书透明日志"));
            idx = h.indexOf(QLatin1Char('.'), idx + 1);
        }
    }

    // 2) 泛解析检测，避免结果被通配 DNS 污染
    const QString rnd = QStringLiteral("src-recon-%1")
                            .arg(QRandomGenerator::global()->generate(), 8, 16, QLatin1Char('0'));
    const QStringList wildIps = NetUtil::resolveHost(rnd + QLatin1Char('.') + root);
    if (!wildIps.isEmpty()) {
        ctx.warn(QStringLiteral("检测到 DNS 泛解析（通配 IP：%1），将过滤命中同一批 IP 的记录")
                     .arg(wildIps.join(QStringLiteral(", "))));
    }

    // 3) 并发 DNS 解析
    const QStringList hosts = candidates.keys();
    const int total = hosts.size();
    ctx.info(QStringLiteral("开始解析 %1 个候选主机名（线程数 %2）")
                 .arg(total)
                 .arg(ctx.pool ? ctx.pool->maxThreadCount() : 0));

    std::atomic<int> done{0};
    QMutex mtx;
    DomainAssetList found;

    QFutureSynchronizer<void> sync;
    for (const QString &h : hosts) {
        sync.addFuture(QtConcurrent::run(ctx.pool, [&, h]() {
            if (ctx.isCancelled())
                return;

            QStringList ips = NetUtil::resolveHost(h);
            if (!wildIps.isEmpty()) {
                for (int i = ips.size() - 1; i >= 0; --i) {
                    if (wildIps.contains(ips.at(i)))
                        ips.removeAt(i);
                }
            }

            if (!ips.isEmpty()) {
                DomainAsset a;
                a.host = h;
                a.ip = ips.first();
                a.source = candidates.value(h);
                QMutexLocker locker(&mtx);
                found.append(a);
            }

            const int d = ++done;
            if (d % 10 == 0 || d == total)
                ctx.progress(d, total);
        }));
    }
    sync.waitForFinished();

    if (ctx.isCancelled()) {
        ctx.warn(QStringLiteral("子域名枚举已被取消"));
        return;
    }

    ctx.addSubdomains(found);
    ctx.ok(QStringLiteral("子域名枚举完成，存活主机 %1 个").arg(found.size()));
}

} // namespace src
