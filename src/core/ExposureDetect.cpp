#include "core/ExposureDetect.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QRegularExpression>
#include <QUrl>

#include "core/Types.h"

namespace src {
namespace exposure {

namespace {

/// 拼接 base 与 path，保证两者之间仅有一个 '/' 分隔，并去除 base 尾部多余的 '/'
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

/// 将可能是相对地址的 raw 依据 baseUrl 解析为绝对地址
QString resolveUrl(const QString &baseUrl, const QString &raw)
{
    const QUrl url = QUrl(baseUrl).resolved(QUrl(raw));
    if (!url.isValid() || url.scheme().isEmpty())
        return QString();
    return url.toString();
}

} // namespace

QStringList apiDocPaths()
{
    return {
        QStringLiteral("/swagger.json"),
        QStringLiteral("/v2/api-docs"),
        QStringLiteral("/v3/api-docs"),
        QStringLiteral("/openapi.json"),
        QStringLiteral("/swagger-resources"),
        QStringLiteral("/actuator"),
        QStringLiteral("/actuator/env"),
        QStringLiteral("/actuator/mappings"),
        QStringLiteral("/actuator/heapdump"),
        QStringLiteral("/actuator/health"),
        QStringLiteral("/druid/index.html"),
        QStringLiteral("/.git/HEAD"),
        QStringLiteral("/.git/config"),
        QStringLiteral("/.env"),
    };
}

QStringList parseOpenApi(const QByteArray &body, const QString &baseUrl,
                         QString *title, QString *version)
{
    QStringList out;

    QJsonParseError err;
    const QJsonDocument doc = QJsonDocument::fromJson(body, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject())
        return out;

    const QJsonObject root = doc.object();

    // 回传文档标题与版本
    const QJsonObject info = root.value(QStringLiteral("info")).toObject();
    if (title)
        *title = info.value(QStringLiteral("title")).toString();
    if (version)
        *version = info.value(QStringLiteral("version")).toString();

    // 规格级前缀：Swagger 2.0 使用 basePath；OpenAPI 3 使用 servers[0].url
    QString prefix;
    const bool isSwagger2 = root.contains(QStringLiteral("swagger"));
    if (isSwagger2)
    {
        prefix = root.value(QStringLiteral("basePath")).toString();
    }
    else
    {
        const QJsonArray servers = root.value(QStringLiteral("servers")).toArray();
        if (!servers.isEmpty())
            prefix = servers.first().toObject().value(QStringLiteral("url")).toString();
    }

    // 计算拼接基址：前缀为绝对地址时直接使用，否则拼接到 baseUrl 之后
    QString base = baseUrl;
    while (base.endsWith(QLatin1Char('/')))
        base.chop(1);

    if (prefix.startsWith(QStringLiteral("http://"))
        || prefix.startsWith(QStringLiteral("https://")))
    {
        base = prefix;
    }
    else
    {
        QString p = prefix;
        while (p.startsWith(QLatin1Char('/')))
            p = p.mid(1);
        while (p.endsWith(QLatin1Char('/')))
            p.chop(1);
        if (!p.isEmpty())
            base += QLatin1Char('/') + p;
    }

    static const QStringList methods = {
        QStringLiteral("get"), QStringLiteral("post"), QStringLiteral("put"),
        QStringLiteral("delete"), QStringLiteral("patch"), QStringLiteral("head"),
        QStringLiteral("options"), QStringLiteral("trace")
    };

    const QJsonObject paths = root.value(QStringLiteral("paths")).toObject();
    for (auto it = paths.constBegin(); it != paths.constEnd(); ++it)
    {
        const QString path = it.key();
        const QJsonObject item = it.value().toObject();

        const QString url = joinUrl(base, path);
        bool hasMethod = false;
        for (const QString &m : methods)
        {
            if (!item.contains(m))
                continue;
            hasMethod = true;
            out << m.toUpper() + QLatin1Char(' ') + url;
        }

        // 无标准方法字段的路径项（例如仅含参数或描述），按 GET 记录
        if (!hasMethod && !item.isEmpty())
            out << QStringLiteral("GET ") + url;
    }

    return out;
}

QStringList parseHtmlForms(const QByteArray &body, const QString &baseUrl)
{
    QStringList out;
    const QString text = QString::fromUtf8(body.left(512 * 1024));

    static const QRegularExpression formRe(
        QStringLiteral("<form\\b[^>]*>([\\s\\S]*?)</form>"),
        QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression actionRe(
        QStringLiteral("\\baction\\s*=\\s*[\"']([^\"']*)[\"']"),
        QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression methodRe(
        QStringLiteral("\\bmethod\\s*=\\s*[\"']([^\"']*)[\"']"),
        QRegularExpression::CaseInsensitiveOption);
    static const QRegularExpression inputRe(
        QStringLiteral("<input\\b[^>]*\\bname\\s*=\\s*[\"']([^\"']+)[\"']"),
        QRegularExpression::CaseInsensitiveOption);

    auto it = formRe.globalMatch(text);
    while (it.hasNext())
    {
        const QRegularExpressionMatch fm = it.next();
        const QString head  = fm.captured(0);
        const QString inner = fm.captured(1);

        QString action;
        const QRegularExpressionMatch am = actionRe.match(head);
        if (am.hasMatch())
            action = am.captured(1).trimmed();

        QString method = QStringLiteral("GET");
        const QRegularExpressionMatch mm = methodRe.match(head);
        if (mm.hasMatch() && !mm.captured(1).trimmed().isEmpty())
            method = mm.captured(1).trimmed().toUpper();

        QStringList params;
        auto ii = inputRe.globalMatch(inner);
        while (ii.hasNext())
        {
            const QString name = ii.next().captured(1).trimmed();
            if (!name.isEmpty() && !params.contains(name))
                params << name;
        }

        QString url = baseUrl;
        if (!action.isEmpty())
        {
            url = resolveUrl(baseUrl, action);
            if (url.isEmpty())
                continue;
        }
        else if (url.isEmpty())
        {
            continue;
        }

        out << method + QLatin1Char(' ') + url
                   + QStringLiteral(" [") + params.join(QLatin1Char(',')) + QStringLiteral("]");
    }

    return out;
}

QStringList parseEnvSecrets(const QByteArray &body)
{
    QStringList out;
    const QString text = QString::fromUtf8(body.left(256 * 1024));

    static const QRegularExpression kvRe(
        QStringLiteral("^\\s*(?:export\\s+)?([A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*(.*)$"));
    static const QStringList sensitive = {
        QStringLiteral("PASSWORD"), QStringLiteral("PASSWD"), QStringLiteral("PWD"),
        QStringLiteral("KEY"), QStringLiteral("TOKEN"), QStringLiteral("SECRET"),
        QStringLiteral("DB_"), QStringLiteral("DATABASE"), QStringLiteral("API")
    };

    const QStringList lines =
        text.split(QRegularExpression(QStringLiteral("[\\r\\n]+")), Qt::SkipEmptyParts);
    for (const QString &line : lines)
    {
        if (line.trimmed().startsWith(QLatin1Char('#')))
            continue;

        const QRegularExpressionMatch m = kvRe.match(line);
        if (!m.hasMatch())
            continue;

        const QString upper = m.captured(1).toUpper();
        for (const QString &kw : sensitive)
        {
            if (upper.contains(kw))
            {
                out << m.captured(1);
                break;
            }
        }
    }

    out.removeDuplicates();
    return out;
}

QString judgeExposure(const QString &path, int code, const QByteArray &body)
{
    const QString p = path.toLower();

    if (code == 401)
        return QStringLiteral("未授权访问：需认证");
    if (code == 403)
        return QStringLiteral("禁止访问（可能存在）");
    if (code == 404 || code == 400)
        return QStringLiteral("不存在");

    if (code == 200)
    {
        if (p.contains(QStringLiteral(".git")) || p.contains(QStringLiteral(".svn"))
            || p.contains(QStringLiteral(".env")))
            return QStringLiteral("敏感文件泄露");
        if (p.contains(QStringLiteral("heapdump")))
            return QStringLiteral("配置泄露：堆转储文件");
        if (p.contains(QStringLiteral("actuator/env")) || p.contains(QStringLiteral("config")))
            return QStringLiteral("配置泄露");
        if (p.contains(QStringLiteral("actuator")))
            return QStringLiteral("未授权访问：Actuator 端点");
        if (p.contains(QStringLiteral("druid")))
            return QStringLiteral("未授权访问：Druid 监控页");
        if (p.contains(QStringLiteral("swagger")) || p.contains(QStringLiteral("api-docs"))
            || p.contains(QStringLiteral("openapi")))
            return QStringLiteral("接口清单泄露");
        if (!body.isEmpty())
            return QStringLiteral("信息泄露");
        return QStringLiteral("可访问");
    }

    if (code >= 500)
        return QStringLiteral("服务器错误");
    return statusNote(code);
}

} // namespace exposure
} // namespace src