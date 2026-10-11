#include "core/JsExtract.h"

#include <QRegularExpression>
#include <QSet>
#include <QUrl>

namespace src {
namespace jsx {

namespace {

/// 把候选地址规范化为绝对 http(s) 地址，无效返回空
QString toAbsolute(const QString &baseUrl, const QString &raw)
{
    const QString v = raw.trimmed();
    if (v.isEmpty())
        return QString();

    const QString low = v.toLower();
    if (low.startsWith(QStringLiteral("javascript:"))
        || low.startsWith(QStringLiteral("mailto:"))
        || low.startsWith(QStringLiteral("data:"))
        || low.startsWith(QStringLiteral("#")))
        return QString();

    QUrl url = QUrl(baseUrl).resolved(QUrl(v));
    if (!url.isValid())
        return QString();
    if (url.scheme() != QLatin1String("http") && url.scheme() != QLatin1String("https"))
        return QString();
    url.setFragment(QString());
    return url.toString();
}

} // namespace

QStringList extractEndpoints(const QByteArray &body, const QString &baseUrl)
{
    QStringList out;
    const QString text = QString::fromUtf8(body.left(800 * 1024));

    // 1) 引号包裹的接口路径，聚焦常见 API 前缀
    static const QRegularExpression pathRe(
        QStringLiteral("[\"'](/(?:api|rest|graphql|open|gateway|v[0-9]|admin|user|users|"
                       "system|order|pay|auth|upload|download|file|files|service|services)"
                       "[a-zA-Z0-9_\\-./?=&%:#]*)[\"']"),
        QRegularExpression::CaseInsensitiveOption);

    // 2) fetch / axios / XMLHttpRequest.open 等调用目标
    static const QRegularExpression callRe(
        QStringLiteral("(?:fetch|axios(?:\\.[a-z]+)?|\\.open)\\s*\\(\\s*[\"'`]([^\"'`\\s]{2,})[\"'`]"),
        QRegularExpression::CaseInsensitiveOption);

    // 3) JS 中的绝对地址（含 .json/.do/.action 等常见接口后缀）
    static const QRegularExpression absRe(
        QStringLiteral("[\"'](https?://[a-z0-9\\-._]+[^\"'\\s<>]*?)"
                       "(?:\\.json|\\.do|\\.action|\\.jsp|\\.php|\\.aspx|/[a-z0-9_\\-]+)[^\"'\\s<>]*[\"']"),
        QRegularExpression::CaseInsensitiveOption);

    QSet<QString> seen;

    auto collect = [&](const QRegularExpression &re, int group) {
        auto it = re.globalMatch(text);
        while (it.hasNext())
        {
            const QRegularExpressionMatch m = it.next();
            const QString abs = toAbsolute(baseUrl, m.captured(group));
            if (!abs.isEmpty() && !seen.contains(abs))
            {
                seen.insert(abs);
                out << abs;
            }
        }
    };

    collect(pathRe, 1);
    collect(callRe, 1);
    collect(absRe, 1);

    return out;
}

QStringList extractSecrets(const QByteArray &body)
{
    QStringList out;
    const QString text = QString::fromUtf8(body.left(800 * 1024));

    // 常见凭据键值对
    static const QRegularExpression kvRe(
        QStringLiteral("(?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key|secret|"
                       "access[_-]?token|auth[_-]?token|token|password|passwd|pwd)"
                       "[\"']?\\s*[:=]\\s*[\"']([A-Za-z0-9_\\-./+=]{6,64})[\"']"),
        QRegularExpression::CaseInsensitiveOption);

    // AWS AccessKeyId
    static const QRegularExpression akRe(
        QStringLiteral("\\b(AKIA[0-9A-Z]{16})\\b"));

    QSet<QString> seen;

    auto it = kvRe.globalMatch(text);
    while (it.hasNext())
    {
        const QRegularExpressionMatch m = it.next();
        const QString name = m.captured(0).section(QLatin1Char(':'), 0, 0)
                                 .section(QLatin1Char('='), 0, 0).trimmed();
        const QString val = m.captured(1);
        const QString item = QStringLiteral("%1 = %2").arg(name, val);
        if (!seen.contains(item))
        {
            seen.insert(item);
            out << item;
        }
    }

    auto ak = akRe.globalMatch(text);
    while (ak.hasNext())
    {
        const QString v = ak.next().captured(1);
        const QString item = QStringLiteral("AWS AccessKeyId = %1").arg(v);
        if (!seen.contains(item))
        {
            seen.insert(item);
            out << item;
        }
    }

    return out;
}

} // namespace jsx
} // namespace src