#include "modules/ExposureModule.h"

#include <QFutureSynchronizer>
#include <QMutex>
#include <QMutexLocker>
#include <QSet>
#include <QStringList>
#include <QThreadPool>
#include <QUrl>
#include <QtConcurrent/QtConcurrentRun>

#include <algorithm>
#include <atomic>

#include "core/ExposureDetect.h"
#include "core/NetUtil.h"

namespace src {

namespace {

/// 拼接 base 与 path，保证两者之间仅有一个 '/' 分隔
QString joinUrl(const QString &base, const QString &path)
{
    QString b = base;
    while (b.endsWith(QLatin1Char('/')))
        b.chop(1);

    QString p = path;
    while (p.startsWith(QLatin1Char('/')))
        p = p.mid(1);

    if (p.isEmpty())
        return b + QLatin1Char('/');
    return b + QLatin1Char('/') + p;
}

/// 依据探测路径推断来源
QString sourceOfDocPath(const QString &path)
{
    const QString p = path.toLower();
    if (p.contains(QStringLiteral("swagger")) || p.contains(QStringLiteral("v2/api-docs")))
        return QStringLiteral("Swagger");
    if (p.contains(QStringLiteral("v3/api-docs")) || p.contains(QStringLiteral("openapi")))
        return QStringLiteral("OpenAPI");
    if (p.contains(QStringLiteral("actuator")))
        return QStringLiteral("Actuator");
    if (p.contains(QStringLiteral("druid")) || p.contains(QStringLiteral(".git"))
        || p.contains(QStringLiteral(".env")))
        return QStringLiteral("敏感文件");
    return QStringLiteral("敏感文件");
}

/// 判断该路径是否为可解析的接口文档（JSON）
bool isJsonDoc(const QString &path)
{
    const QString p = path.toLower();
    return p.contains(QStringLiteral("api-docs")) || p.contains(QStringLiteral("swagger.json"))
           || p.contains(QStringLiteral("openapi.json"));
}

/// 依据风险说明推断风险等级
QString severityOf(const QString &note)
{
    if (note.contains(QStringLiteral("敏感文件")))
        return QStringLiteral("高");
    if (note.contains(QStringLiteral("配置泄露")))
        return QStringLiteral("高");
    if (note.contains(QStringLiteral("未授权访问")))
        return QStringLiteral("高");
    if (note.contains(QStringLiteral("接口清单")))
        return QStringLiteral("中");
    if (note.contains(QStringLiteral("信息泄露")))
        return QStringLiteral("中");
    if (note.contains(QStringLiteral("可访问")))
        return QStringLiteral("低");
    return QStringLiteral("信息");
}

/// 拆解 "METHOD url [params]" 形式的表单记录
ApiEndpoint parseForm(const QString &line)
{
    ApiEndpoint ep;
    ep.method = QStringLiteral("GET");
    ep.url    = line;

    const int sp = line.indexOf(QLatin1Char(' '));
    if (sp <= 0)
        return ep;

    ep.method = line.left(sp);
    QString rest = line.mid(sp + 1);

    const int bp = rest.indexOf(QStringLiteral(" ["));
    if (bp >= 0)
    {
        ep.params = rest.mid(bp + 2);
        if (ep.params.endsWith(QLatin1Char(']')))
            ep.params.chop(1);
        ep.params = ep.params.trimmed();
        rest = rest.left(bp);
    }
    ep.url = rest.trimmed();
    return ep;
}

} // namespace

void ExposureModule::run(ModuleContext &ctx)
{
    const EngineOptions &o = *ctx.opt;

    if (o.demo)
    {
        ctx.info(QStringLiteral("演示模式：返回内置接口/暴露面数据"));

        ApiEndpointList list;
        auto add = [&list](const QString &url, const QString &method, const QString &source,
                           int code, const QString &params, const QString &severity,
                           const QString &note) {
            ApiEndpoint e;
            e.url        = url;
            e.method     = method;
            e.source     = source;
            e.statusCode = code;
            e.params     = params;
            e.severity   = severity;
            e.note       = note;
            list << e;
        };

        const QString base = o.baseUrl.isEmpty() ? QStringLiteral("http://example.com")
                                                 : o.baseUrl;
        add(joinUrl(base, QStringLiteral("v3/api-docs")), QStringLiteral("GET"),
            QStringLiteral("OpenAPI"), 200, QString(),
            QStringLiteral("中"), QStringLiteral("接口清单泄露"));
        add(joinUrl(base, QStringLiteral("actuator/env")), QStringLiteral("GET"),
            QStringLiteral("Actuator"), 200, QString(),
            QStringLiteral("高"), QStringLiteral("配置泄露"));
        add(joinUrl(base, QStringLiteral(".env")), QStringLiteral("GET"),
            QStringLiteral("敏感文件"), 200, QString(),
            QStringLiteral("高"), QStringLiteral("敏感文件泄露"));
        add(joinUrl(base, QStringLiteral("api/user/list")), QStringLiteral("GET"),
            QStringLiteral("JS接口"), 200, QStringLiteral("page,size"),
            QStringLiteral("信息"), QStringLiteral("信息泄露"));
        add(joinUrl(base, QStringLiteral("login")), QStringLiteral("POST"),
            QStringLiteral("表单"), 200, QStringLiteral("username,password"),
            QStringLiteral("信息"), QStringLiteral("表单提交接口"));

        ctx.progress(list.size(), list.size());
        ctx.addEndpoints(list);
        ctx.ok(QStringLiteral("暴露面分析完成（演示数据）"));
        return;
    }

    // 串联：对每个存活的 Web 服务做暴露面探测，并补充根目标
    QStringList targets;
    if (ctx.state)
        targets = ctx.state->aliveWeb();
    QString fallback = o.baseUrl;
    if (fallback.isEmpty() && !o.host.isEmpty())
        fallback = QStringLiteral("http://") + o.host;
    if (!fallback.isEmpty() && !targets.contains(fallback))
        targets.prepend(fallback);
    targets.removeDuplicates();

    const int cap = qMax(1, o.maxWebTargets);
    if (targets.size() > cap)
    {
        ctx.warn(QStringLiteral("暴露面探测目标 %1 个，超出上限 %2，仅探测前 %2 个")
                     .arg(targets.size()).arg(cap));
        targets = targets.mid(0, cap);
    }
    if (targets.isEmpty())
    {
        ctx.error(QStringLiteral("目标为空，跳过接口/暴露面分析"));
        return;
    }

    const QStringList docPaths = exposure::apiDocPaths();
    const QStringList candidates =
        ctx.state ? ctx.state->endpointCandidates() : QStringList();

    // 组装探测任务：敏感文档路径 + 爬虫提取的接口候选
    struct Probe
    {
        QString url;
        QString path;
        QString source;
        bool    jsonDoc = false;
    };

    QVector<Probe> probes;
    for (const QString &base : targets)
    {
        for (const QString &p : docPaths)
        {
            Probe pr;
            pr.url     = joinUrl(base, p);
            pr.path    = p;
            pr.source  = sourceOfDocPath(p);
            pr.jsonDoc = isJsonDoc(p);
            probes << pr;
        }
    }
    for (const QString &c : candidates)
    {
        Probe pr;
        pr.url    = c;
        pr.path   = QUrl(c).path();
        pr.source = QStringLiteral("JS接口");
        probes << pr;
    }

    const int maxProbe = qMax(1, o.exposureMaxProbe);
    if (probes.size() > maxProbe)
    {
        ctx.warn(QStringLiteral("暴露面探测请求 %1 个，超出上限 %2，仅探测前 %2 个")
                     .arg(probes.size()).arg(maxProbe));
        probes = probes.mid(0, maxProbe);
    }

    ctx.info(QStringLiteral("暴露面探测：目标 %1 个，文档/接口任务 %2 个，爬虫候选 %3 个")
                 .arg(targets.size()).arg(probes.size()).arg(candidates.size()));

    QMutex mtx;
    QSet<QString> seen;
    ApiEndpointList hits;
    std::atomic<int> done{0};
    const int total = probes.size() + targets.size();

    auto push = [&](const ApiEndpoint &e) {
        if (e.url.isEmpty())
            return;
        QMutexLocker locker(&mtx);
        const QString key = e.method + QLatin1Char('|') + e.url;
        if (seen.contains(key))
            return;
        seen.insert(key);
        hits << e;
    };

    QFutureSynchronizer<void> sync;

    // 1) 探测文档路径与爬虫候选
    for (const Probe &pr : probes)
    {
        sync.addFuture(QtConcurrent::run(ctx.pool, [&, pr]() {
            if (ctx.isCancelled())
                return;

            const HttpResponse res = NetUtil::httpRequest(pr.url, o.timeoutMs);
            const int d = ++done;
            if (d % 10 == 0 || d == total)
                ctx.progress(d, total);

            if (res.statusCode <= 0)
                return;

            // JS 候选接口：只要可访问即记录
            if (pr.source == QStringLiteral("JS接口"))
            {
                if (res.statusCode == 200)
                {
                    ApiEndpoint e;
                    e.url        = pr.url;
                    e.method     = QStringLiteral("GET");
                    e.source     = pr.source;
                    e.statusCode = res.statusCode;
                    e.note       = exposure::judgeExposure(pr.path, res.statusCode, res.body);
                    e.severity   = severityOf(e.note);
                    push(e);
                }
                return;
            }

            if (res.statusCode != 200)
                return;

            // 接口文档：解析出真实接口清单
            if (pr.jsonDoc)
            {
                QString title;
                QString version;
                const QStringList eps =
                    exposure::parseOpenApi(res.body, pr.url, &title, &version);
                if (!eps.isEmpty())
                {
                    for (const QString &line : eps)
                    {
                        ApiEndpoint e;
                        const int sp = line.indexOf(QLatin1Char(' '));
                        e.method = sp > 0 ? line.left(sp) : QStringLiteral("GET");
                        e.url    = sp > 0 ? line.mid(sp + 1) : line;
                        e.source = pr.source;
                        e.note   = QStringLiteral("接口清单泄露");
                        if (!title.isEmpty())
                            e.note += QStringLiteral("：%1").arg(title);
                        if (!version.isEmpty())
                            e.note += QStringLiteral(" (%1)").arg(version);
                        e.severity   = QStringLiteral("中");
                        e.statusCode = res.statusCode;
                        push(e);
                    }
                    return;
                }
            }

            // 其余敏感路径命中
            ApiEndpoint e;
            e.url        = pr.url;
            e.method     = QStringLiteral("GET");
            e.source     = pr.source;
            e.statusCode = res.statusCode;
            e.note       = exposure::judgeExposure(pr.path, res.statusCode, res.body);
            e.severity   = severityOf(e.note);

            // .env 命中时提取敏感键名作为补充信息
            if (pr.path.toLower().contains(QStringLiteral(".env")))
            {
                const QStringList keys = exposure::parseEnvSecrets(res.body);
                if (!keys.isEmpty())
                {
                    e.params = keys.join(QLatin1Char(','));
                    e.note += QStringLiteral("（敏感键 %1 个）").arg(keys.size());
                }
            }
            push(e);
        }));
    }

    // 2) 抓取存活页面并解析表单
    for (const QString &base : targets)
    {
        sync.addFuture(QtConcurrent::run(ctx.pool, [&, base]() {
            if (ctx.isCancelled())
                return;

            const HttpResponse res = NetUtil::httpRequest(base, o.timeoutMs);
            const int d = ++done;
            if (d % 10 == 0 || d == total)
                ctx.progress(d, total);

            if (res.statusCode != 200 || res.body.isEmpty())
                return;

            const QStringList forms = exposure::parseHtmlForms(res.body, base);
            for (const QString &line : forms)
            {
                ApiEndpoint e = parseForm(line);
                if (e.url.isEmpty())
                    continue;
                e.source     = QStringLiteral("表单");
                e.statusCode = res.statusCode;
                e.note       = QStringLiteral("表单提交接口");
                e.severity   = QStringLiteral("信息");
                push(e);
            }
        }));
    }

    sync.waitForFinished();

    if (ctx.isCancelled())
    {
        ctx.warn(QStringLiteral("接口/暴露面分析已被取消"));
        return;
    }

    std::sort(hits.begin(), hits.end(), [](const ApiEndpoint &a, const ApiEndpoint &b) {
        if (a.severity != b.severity)
            return a.severity < b.severity;
        if (a.url != b.url)
            return a.url < b.url;
        return a.method < b.method;
    });

    ctx.addEndpoints(hits);
    ctx.ok(QStringLiteral("接口/暴露面分析完成，共记录 %1 条接口/敏感面").arg(hits.size()));
}

} // namespace src