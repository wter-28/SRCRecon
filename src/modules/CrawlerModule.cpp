#include "modules/CrawlerModule.h"

#include <QFutureSynchronizer>
#include <QMutex>
#include <QMutexLocker>
#include <QRegularExpression>
#include <QSet>
#include <QThreadPool>
#include <QUrl>
#include <QtConcurrent/QtConcurrentRun>

#include <algorithm>
#include <atomic>

#include "core/DemoData.h"
#include "core/NetUtil.h"

namespace src {

namespace {

/// 判断是否为可继续抓取解析的页面类型
bool isCrawlable(const QString &contentType)
{
    const QString ct = contentType.toLower();
    return ct.isEmpty() || ct.contains(QStringLiteral("html")) || ct.contains(QStringLiteral("xml"))
           || ct.contains(QStringLiteral("json")) || ct.contains(QStringLiteral("javascript"))
           || ct.contains(QStringLiteral("text/plain"));
}

/// 从 HTML/JS 文本中提取候选链接
QStringList extractLinks(const QByteArray &body)
{
    static const QRegularExpression attrRe(
        QStringLiteral("(?:href|src|action|data-url|url)\\s*=\\s*[\"']([^\"'#\\s]+)[\"']"),
        QRegularExpression::CaseInsensitiveOption);

    static const QRegularExpression quotedRe(
        QStringLiteral("[\"']((?:https?:)?//[a-z0-9\\-._]+[^\"'\\s<>]*)[\"']"),
        QRegularExpression::CaseInsensitiveOption);

    const QString text = QString::fromUtf8(body.left(500 * 1024));

    QStringList links;
    auto collect = [&links, &text](const QRegularExpression &re) {
        auto it = re.globalMatch(text);
        while (it.hasNext()) {
            const QRegularExpressionMatch m = it.next();
            const QString v = m.captured(1).trimmed();
            if (!v.isEmpty())
                links << v;
        }
    };
    collect(attrRe);
    collect(quotedRe);
    links.removeDuplicates();
    return links;
}

/// 规范化 URL：过滤无效协议与静态资源中的非页面类型
QString normalizeUrl(const QString &baseUrl, const QString &raw)
{
    if (raw.isEmpty())
        return QString();

    const QString low = raw.toLower();
    if (low.startsWith(QStringLiteral("javascript:"))
        || low.startsWith(QStringLiteral("mailto:"))
        || low.startsWith(QStringLiteral("tel:"))
        || low.startsWith(QStringLiteral("data:"))
        || low.startsWith(QStringLiteral("about:"))
        || low.startsWith(QStringLiteral("#")))
        return QString();

    QUrl url = QUrl(baseUrl).resolved(QUrl(raw));
    if (!url.isValid() || url.scheme().isEmpty())
        return QString();
    if (url.scheme() != QLatin1String("http") && url.scheme() != QLatin1String("https"))
        return QString();

    url.setFragment(QString());
    return url.toString();
}

/// 依据扩展名判断资源来源类型
QString sourceOf(const QString &url)
{
    const QString path = QUrl(url).path().toLower();
    if (path.endsWith(QStringLiteral(".js")))  return QStringLiteral("JS文件");
    if (path.endsWith(QStringLiteral(".css"))) return QStringLiteral("样式文件");
    if (path.endsWith(QStringLiteral(".json")))return QStringLiteral("数据文件");
    if (path.endsWith(QStringLiteral(".pdf"))) return QStringLiteral("文档");
    return QStringLiteral("爬虫页面");
}

} // namespace

void CrawlerModule::run(ModuleContext &ctx)
{
    const EngineOptions &o = *ctx.opt;

    if (o.demo) {
        ctx.info(QStringLiteral("演示模式：返回内置链接数据"));
        const UrlRecordList list =
            demo::urls(o.baseUrl.isEmpty() ? QStringLiteral("http://example.com") : o.baseUrl);
        ctx.progress(list.size(), list.size());
        ctx.addUrls(list);
        ctx.ok(QStringLiteral("收集到 %1 条链接（演示数据）").arg(list.size()));
        return;
    }

    QString start = o.baseUrl;
    if (start.isEmpty() && !o.host.isEmpty())
        start = QStringLiteral("http://") + o.host;
    if (start.isEmpty()) {
        ctx.error(QStringLiteral("目标为空，跳过爬虫"));
        return;
    }

    const QUrl startUrl(start);
    const QString rootHost = startUrl.host();
    const int maxPages = qMax(1, o.crawlMaxPages);
    const int maxDepth = qMax(0, o.crawlDepth);

    ctx.info(QStringLiteral("起始地址：%1，最大页面数：%2，最大深度：%3，跟随站外：%4")
                 .arg(start)
                 .arg(maxPages)
                 .arg(maxDepth)
                 .arg(o.crawlExternal ? QStringLiteral("是") : QStringLiteral("否")));

    struct Item { QString url; int depth; };

    QVector<Item> current;
    current << Item{start, 0};

    QSet<QString> visited;
    visited.insert(start);

    QMutex mtx;
    UrlRecordList records;
    std::atomic<int> fetched{0};

    while (!current.isEmpty() && !ctx.isCancelled()) {
        // 达到上限则截断本层任务
        QVector<Item> wave = current;
        if (wave.size() > maxPages - fetched.load())
            wave = wave.mid(0, qMax(0, maxPages - fetched.load()));
        if (wave.isEmpty())
            break;

        QVector<Item> next;

        QFutureSynchronizer<void> sync;
        for (const Item &item : wave) {
            sync.addFuture(QtConcurrent::run(ctx.pool, [&, item]() {
                if (ctx.isCancelled())
                    return;

                const HttpResponse res = NetUtil::httpRequest(item.url, o.timeoutMs);

                UrlRecord rec;
                rec.url         = item.url;
                rec.statusCode  = res.statusCode;
                rec.contentType = res.contentType().section(QLatin1Char(';'), 0, 0);
                rec.length      = res.contentLength();
                rec.source      = sourceOf(item.url);

                {
                    QMutexLocker locker(&mtx);
                    records.append(rec);
                }

                const int d = ++fetched;
                ctx.progress(qMin(d, maxPages), maxPages);

                // 仅在还有深度余量且内容可解析时继续提取
                if (item.depth >= maxDepth || !res.ok || !isCrawlable(rec.contentType))
                    return;

                const QStringList rawLinks = extractLinks(res.body);
                QVector<Item> local;
                for (const QString &raw : rawLinks) {
                    const QString abs = normalizeUrl(item.url, raw);
                    if (abs.isEmpty())
                        continue;

                    const bool sameHost = QUrl(abs).host().compare(rootHost, Qt::CaseInsensitive) == 0;
                    if (!sameHost && !o.crawlExternal)
                        continue;

                    {
                        QMutexLocker locker(&mtx);
                        if (visited.contains(abs))
                            continue;
                        visited.insert(abs);
                    }

                    local << Item{abs, item.depth + 1};
                }

                if (!local.isEmpty()) {
                    QMutexLocker locker(&mtx);
                    next += local;
                }
            }));
        }
        sync.waitForFinished();

        current = next;
    }

    if (ctx.isCancelled())
        ctx.warn(QStringLiteral("爬虫已被取消"));

    // 站外链接单独补充记录
    for (const QString &u : visited) {
        if (QUrl(u).host().compare(rootHost, Qt::CaseInsensitive) != 0) {
            UrlRecord r;
            r.url = u;
            r.source = QStringLiteral("站外链接");
            records << r;
        }
    }

    std::sort(records.begin(), records.end(),
              [](const UrlRecord &a, const UrlRecord &b) { return a.url < b.url; });

    ctx.addUrls(records);
    ctx.ok(QStringLiteral("爬取完成，共记录 %1 条 URL").arg(records.size()));
}

} // namespace src
