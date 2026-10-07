#include "modules/WebFingerModule.h"

#include <QRegularExpression>
#include <QStringList>

#include "core/DemoData.h"
#include "core/NetUtil.h"

namespace src {

namespace {

QString extractTitle(const QByteArray &body)
{
    static const QRegularExpression re(
        QStringLiteral("<title[^>]*>(.*?)</title>"),
        QRegularExpression::CaseInsensitiveOption | QRegularExpression::DotMatchesEverythingOption);

    const QString html = QString::fromUtf8(body.left(200 * 1024));
    const QRegularExpressionMatch m = re.match(html);
    if (!m.hasMatch())
        return QString();

    QString t = m.captured(1).simplified();
    t.replace(QLatin1Char('\n'), QLatin1Char(' '));
    return t.left(200);
}

/// 综合响应头与页面内容识别技术栈
QString detectTechnologies(const HttpResponse &res)
{
    QStringList tech;
    auto add = [&tech](const QString &s) {
        if (!s.isEmpty() && !tech.contains(s))
            tech << s;
    };

    const QString server  = res.header(QStringLiteral("server")).toLower();
    const QString powered = res.header(QStringLiteral("x-powered-by")).toLower();
    const QString cookies = res.header(QStringLiteral("set-cookie")).toLower();
    const QString body    = QString::fromUtf8(res.body.left(200 * 1024)).toLower();

    // 服务端 / 中间件
    if (server.contains(QStringLiteral("openresty")))    add(QStringLiteral("OpenResty"));
    else if (server.contains(QStringLiteral("nginx")))   add(QStringLiteral("Nginx"));
    if (server.contains(QStringLiteral("apache")))       add(QStringLiteral("Apache"));
    if (server.contains(QStringLiteral("microsoft-iis")))add(QStringLiteral("IIS"));
    if (server.contains(QStringLiteral("tengine")))      add(QStringLiteral("Tengine"));
    if (server.contains(QStringLiteral("caddy")))        add(QStringLiteral("Caddy"));
    if (server.contains(QStringLiteral("gunicorn")))     add(QStringLiteral("Gunicorn"));
    if (server.contains(QStringLiteral("jetty")))        add(QStringLiteral("Jetty"));
    if (server.contains(QStringLiteral("coyote"))
        || server.contains(QStringLiteral("tomcat")))    add(QStringLiteral("Tomcat"));

    // 后端语言
    if (powered.contains(QStringLiteral("php")))         add(QStringLiteral("PHP"));
    if (powered.contains(QStringLiteral("asp.net")))     add(QStringLiteral("ASP.NET"));
    if (powered.contains(QStringLiteral("express")))     add(QStringLiteral("Express"));
    if (powered.contains(QStringLiteral("servlet")))     add(QStringLiteral("Servlet"));
    if (cookies.contains(QStringLiteral("phpsessid")))   add(QStringLiteral("PHP"));
    if (cookies.contains(QStringLiteral("jsessionid")))  add(QStringLiteral("Java"));
    if (cookies.contains(QStringLiteral("asp.net_sessionid"))) add(QStringLiteral("ASP.NET"));
    if (cookies.contains(QStringLiteral("rememberme")))  add(QStringLiteral("Apache Shiro"));
    if (cookies.contains(QStringLiteral("csrftoken")))   add(QStringLiteral("Django"));

    // 框架 / CMS / 前端库
    if (body.contains(QStringLiteral("wp-content"))
        || body.contains(QStringLiteral("wp-includes")))  add(QStringLiteral("WordPress"));
    if (body.contains(QStringLiteral("thinkphp")))        add(QStringLiteral("ThinkPHP"));
    if (body.contains(QStringLiteral("whitelabel error page"))) add(QStringLiteral("Spring Boot"));
    if (body.contains(QStringLiteral("spring")))          add(QStringLiteral("Spring"));
    if (body.contains(QStringLiteral("struts")))          add(QStringLiteral("Struts2"));
    if (body.contains(QStringLiteral("shiro")))           add(QStringLiteral("Apache Shiro"));
    if (body.contains(QStringLiteral("dedecms"))
        || body.contains(QStringLiteral("/dede/")))        add(QStringLiteral("DedeCMS"));
    if (body.contains(QStringLiteral("discuz")))          add(QStringLiteral("Discuz"));
    if (body.contains(QStringLiteral("phpmyadmin")))      add(QStringLiteral("phpMyAdmin"));
    if (body.contains(QStringLiteral("_next/static")))    add(QStringLiteral("Next.js"));
    if (body.contains(QStringLiteral("react")))           add(QStringLiteral("React"));
    if (body.contains(QStringLiteral("data-v-"))
        || body.contains(QStringLiteral("vue.js"))
        || body.contains(QStringLiteral("vue.min.js")))    add(QStringLiteral("Vue"));
    if (body.contains(QStringLiteral("jquery")))          add(QStringLiteral("jQuery"));
    if (body.contains(QStringLiteral("bootstrap")))       add(QStringLiteral("Bootstrap"));
    if (body.contains(QStringLiteral("element-ui")))      add(QStringLiteral("ElementUI"));
    if (body.contains(QStringLiteral("ant-design")))      add(QStringLiteral("Ant Design"));
    if (body.contains(QStringLiteral("layui")))           add(QStringLiteral("Layui"));
    if (body.contains(QStringLiteral("webpack")))         add(QStringLiteral("Webpack"));

    return tech.join(QStringLiteral(", "));
}

/// 汇总关键响应头
QString collectHeaders(const HttpResponse &res)
{
    static const QStringList keys = {
        QStringLiteral("x-powered-by"), QStringLiteral("x-application-context"),
        QStringLiteral("via"), QStringLiteral("x-frame-options"),
        QStringLiteral("content-security-policy"), QStringLiteral("x-aspnet-version"),
        QStringLiteral("set-cookie"), QStringLiteral("location")
    };

    QStringList out;
    for (const QString &k : keys) {
        const QString v = res.header(k);
        if (!v.isEmpty()) {
            QString val = v;
            if (k == QStringLiteral("set-cookie"))
                val = val.section(QLatin1Char('='), 0, 0).trimmed() + QStringLiteral("=...");
            out << QStringLiteral("%1: %2").arg(k, val.left(120));
        }
    }
    return out.join(QStringLiteral("; "));
}

/// 组装探测目标：原始 URL 及其另一种协议的入口
QStringList buildTargets(const EngineOptions &o)
{
    QStringList targets;
    QString base = o.baseUrl;
    if (base.isEmpty() && !o.host.isEmpty())
        base = QStringLiteral("http://") + o.host;
    if (base.isEmpty())
        return targets;

    targets << base;
    if (base.startsWith(QStringLiteral("http://")))
        targets << QStringLiteral("https://") + base.mid(7);
    else if (base.startsWith(QStringLiteral("https://")))
        targets << QStringLiteral("http://") + base.mid(8);

    targets.removeDuplicates();
    return targets;
}

} // namespace

void WebFingerModule::run(ModuleContext &ctx)
{
    const EngineOptions &o = *ctx.opt;

    if (o.demo) {
        ctx.info(QStringLiteral("演示模式：返回内置指纹数据"));
        const WebFingerprintList list =
            demo::fingerprints(o.baseUrl.isEmpty() ? QStringLiteral("http://example.com") : o.baseUrl);
        ctx.progress(list.size(), list.size());
        ctx.addFingerprints(list);
        ctx.ok(QStringLiteral("识别到 %1 条指纹记录（演示数据）").arg(list.size()));
        return;
    }

    const QStringList targets = buildTargets(o);
    if (targets.isEmpty()) {
        ctx.error(QStringLiteral("目标为空，跳过指纹识别"));
        return;
    }

    WebFingerprintList out;
    for (int i = 0; i < targets.size(); ++i) {
        if (ctx.isCancelled())
            return;

        const QString url = targets.at(i);
        ctx.info(QStringLiteral("指纹探测：%1").arg(url));

        const HttpResponse res = NetUtil::httpRequest(url, o.timeoutMs);
        if (!res.ok && res.statusCode == 0) {
            ctx.warn(QStringLiteral("请求失败：%1").arg(res.errorString));
            ctx.progress(i + 1, targets.size());
            continue;
        }

        WebFingerprint fp;
        fp.url          = res.finalUrl.isEmpty() ? url : res.finalUrl;
        fp.statusCode   = res.statusCode;
        fp.title        = extractTitle(res.body);
        fp.server       = res.header(QStringLiteral("server"));
        fp.poweredBy    = res.header(QStringLiteral("x-powered-by"));
        fp.technologies = detectTechnologies(res);
        fp.extraHeaders = collectHeaders(res);
        out << fp;

        ctx.ok(QStringLiteral("[%1] %2 | 标题：%3 | 指纹：%4")
                   .arg(res.statusCode)
                   .arg(fp.url)
                   .arg(fp.title.isEmpty() ? QStringLiteral("-") : fp.title)
                   .arg(fp.technologies.isEmpty() ? QStringLiteral("-") : fp.technologies));

        ctx.progress(i + 1, targets.size());
    }

    if (!out.isEmpty())
        ctx.addFingerprints(out);
    ctx.ok(QStringLiteral("指纹识别完成，共 %1 条记录").arg(out.size()));
}

} // namespace src
