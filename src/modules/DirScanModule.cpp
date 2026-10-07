#include "modules/DirScanModule.h"

#include <QFutureSynchronizer>
#include <QMutex>
#include <QMutexLocker>
#include <QRandomGenerator>
#include <QThreadPool>
#include <QUrl>
#include <QtConcurrent/QtConcurrentRun>

#include <algorithm>
#include <atomic>

#include "core/DemoData.h"
#include "core/NetUtil.h"
#include "core/Wordlists.h"

namespace src {

namespace {

QString joinUrl(const QString &base, const QString &path)
{
    QString b = base;
    while (b.endsWith(QLatin1Char('/')))
        b.chop(1);
    QString p = path;
    while (p.startsWith(QLatin1Char('/')))
        p = p.mid(1);
    return b + QLatin1Char('/') + p;
}

/// 依据路径关键字与状态码给出提示
QString riskNote(const QString &path, int code)
{
    if (code == 403) return QStringLiteral("禁止访问（可能存在）");
    if (code == 401) return QStringLiteral("需认证");
    if (code == 302 || code == 301) return QStringLiteral("跳转");

    const QString p = path.toLower();
    if (code == 200) {
        if (p.contains(QStringLiteral(".git")) || p.contains(QStringLiteral(".svn")))
            return QStringLiteral("源码泄露");
        if (p.contains(QStringLiteral(".env")) || p.contains(QStringLiteral("config")))
            return QStringLiteral("配置泄露");
        if (p.contains(QStringLiteral("backup")) || p.contains(QStringLiteral(".zip"))
            || p.contains(QStringLiteral(".sql")) || p.contains(QStringLiteral(".bak")))
            return QStringLiteral("备份泄露");
        if (p.contains(QStringLiteral("actuator")) || p.contains(QStringLiteral("swagger"))
            || p.contains(QStringLiteral("api-docs")) || p.contains(QStringLiteral("druid")))
            return QStringLiteral("敏感接口");
        if (p.contains(QStringLiteral("phpinfo")) || p.contains(QStringLiteral("server-status")))
            return QStringLiteral("信息泄露");
        if (p.contains(QStringLiteral("admin")) || p.contains(QStringLiteral("manage"))
            || p.contains(QStringLiteral("console")))
            return QStringLiteral("管理入口");
        if (p.contains(QStringLiteral("upload")) || p.contains(QStringLiteral("download")))
            return QStringLiteral("文件目录");
        return QStringLiteral("成功");
    }
    if (code >= 500) return QStringLiteral("服务器错误");
    return statusNote(code);
}

} // namespace

void DirScanModule::run(ModuleContext &ctx)
{
    const EngineOptions &o = *ctx.opt;

    if (o.demo) {
        ctx.info(QStringLiteral("演示模式：返回内置目录探测数据"));
        const DirRecordList list =
            demo::dirs(o.baseUrl.isEmpty() ? QStringLiteral("http://example.com") : o.baseUrl);
        ctx.progress(list.size(), list.size());
        ctx.addDirs(list);
        ctx.ok(QStringLiteral("发现 %1 个有效路径（演示数据）").arg(list.size()));
        return;
    }

    QString base = o.baseUrl;
    if (base.isEmpty() && !o.host.isEmpty())
        base = QStringLiteral("http://") + o.host;
    if (base.isEmpty()) {
        ctx.error(QStringLiteral("目标为空，跳过目录探测"));
        return;
    }

    const QStringList dict = words::loadWordlist(o.dirWordlist, words::directories());
    ctx.info(QStringLiteral("目录字典条目：%1，目标：%2").arg(dict.size()).arg(base));

    // 通配符检测：随机路径若返回 200，说明站点对任意路径都返回有效页面
    const QString rndPath = QStringLiteral("src-recon-%1.html")
                                .arg(QRandomGenerator::global()->generate(), 8, 16, QLatin1Char('0'));
    bool wildcard = false;
    {
        const HttpResponse probe = NetUtil::httpRequest(joinUrl(base, rndPath), o.timeoutMs);
        if (probe.statusCode == 200) {
            wildcard = true;
            ctx.warn(QStringLiteral("检测到通配响应（随机路径返回 200），结果可能存在误报"));
        }
    }

    std::atomic<int> done{0};
    QMutex mtx;
    DirRecordList hits;

    const int total = dict.size();
    QFutureSynchronizer<void> sync;
    for (const QString &path : dict) {
        sync.addFuture(QtConcurrent::run(ctx.pool, [&, path]() {
            if (ctx.isCancelled())
                return;

            const QString url = joinUrl(base, path);
            const HttpResponse res = NetUtil::httpRequest(url, o.timeoutMs);

            const bool interesting = res.statusCode > 0 && res.statusCode != 404
                                     && res.statusCode != 400;
            if (interesting) {
                DirRecord r;
                r.url          = url;
                r.statusCode   = res.statusCode;
                r.length       = res.contentLength();
                r.contentType  = res.contentType().section(QLatin1Char(';'), 0, 0);
                r.note         = riskNote(path, res.statusCode);
                if (wildcard && res.statusCode == 200)
                    r.note += QStringLiteral("（疑似通配）");

                QMutexLocker locker(&mtx);
                hits.append(r);
            }

            const int d = ++done;
            if (d % 20 == 0 || d == total)
                ctx.progress(d, total);
        }));
    }
    sync.waitForFinished();

    if (ctx.isCancelled()) {
        ctx.warn(QStringLiteral("目录探测已被取消"));
        return;
    }

    std::sort(hits.begin(), hits.end(), [](const DirRecord &a, const DirRecord &b) {
        if (a.statusCode != b.statusCode)
            return a.statusCode < b.statusCode;
        return a.url < b.url;
    });

    ctx.addDirs(hits);
    ctx.ok(QStringLiteral("目录探测完成，命中 %1 个路径").arg(hits.size()));
}

} // namespace src
