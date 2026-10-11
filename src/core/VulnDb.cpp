#include "core/VulnDb.h"

#include <QRegularExpression>
#include <QStringList>
#include <QVector>

namespace src {
namespace vulndb {

namespace {

// ---------------- 技术栈 / 产品关键字 -> 漏洞线索 ----------------
struct VulnMarker
{
    QString marker;  // 在技术栈字符串中匹配的关键字（小写）
    QString hint;    // 线索文本
};

const QVector<VulnMarker> &vulnTable()
{
    static const QVector<VulnMarker> t = {
        {QStringLiteral("weblogic"),
         QStringLiteral("WebLogic：关注 CVE-2020-14882/14883 未授权 RCE、CVE-2019-2725 反序列化")},
        {QStringLiteral("struts")  , QStringLiteral("Struts2：关注 S2-045/S2-057 远程代码执行")},
        {QStringLiteral("spring")  , QStringLiteral("Spring：若 actuator 未授权，关注 CVE-2022-22965 与内存/环境泄露")},
        {QStringLiteral("thinkphp"), QStringLiteral("ThinkPHP：关注 5.x 远程代码执行与多语言本地包含")},
        {QStringLiteral("shiro")   , QStringLiteral("Apache Shiro：关注 rememberMe 反序列化（CVE-2016-4437 及其绕过）")},
        {QStringLiteral("dedecms") , QStringLiteral("DedeCMS：关注后台弱口令、任意文件上传/包含及历史变量覆盖漏洞")},
        {QStringLiteral("discuz")  , QStringLiteral("Discuz：关注后台 Getshell、UC_KEY 泄露与 SSRF")},
        {QStringLiteral("jenkins") , QStringLiteral("Jenkins：关注未授权脚本控制台与 CVE-2024-23897 任意文件读取")},
        {QStringLiteral("tomcat")  , QStringLiteral("Tomcat：关注 CVE-2017-12615 PUT 上传、AJP Ghostcat（CVE-2020-1938）")},
        {QStringLiteral("php")     , QStringLiteral("PHP：确认版本并核对已知漏洞，注意 phpinfo/备份文件泄露")},
        {QStringLiteral("jquery")  , QStringLiteral("jQuery：旧版本存在 DOM XSS（CVE-2020-11022/11023），建议升级至 3.5.0+")}
    };
    return t;
}

// ---------------- 版本区间 -> 已知 CVE（启发式表） ----------------
// 说明：版本号来自响应头 / 页面特征，可能不精确；本表仅给出受影响较知名的版本区间，
// 命中即输出“低于安全版本”的提示，结论仅供参考，需人工核实。
struct RangeRule
{
    QString marker;   // 技术在技术栈字符串中的定位关键字（小写）
    int     major;    // 限定主版本，-1 表示不限
    QString below;    // 低于该版本即视为可能受影响
    QString hint;     // 线索模板（%1 = 实际版本号）
};

const QVector<RangeRule> &rangeTable()
{
    static const QVector<RangeRule> t = {
        {QStringLiteral("tomcat"), 9, QStringLiteral("9.0.32"),
         QStringLiteral("Tomcat %1 可能受 Ghostcat（CVE-2020-1938）AJP 文件读取影响，建议升级至 9.0.32+ 并关闭 AJP")},
        {QStringLiteral("shiro"), -1, QStringLiteral("1.2.5"),
         QStringLiteral("Apache Shiro %1 存在 rememberMe 反序列化（CVE-2016-4437，密钥硬编码），建议升级至 1.2.5+")},
        {QStringLiteral("spring"), -1, QStringLiteral("5.3.18"),
         QStringLiteral("Spring %1 可能受 CVE-2022-22965（Spring4Shell）影响，建议升级至 5.3.18+ / 2.6.6+")},
        {QStringLiteral("jquery"), -1, QStringLiteral("3.5.0"),
         QStringLiteral("jQuery %1 存在 CVE-2020-11022/11023 XSS，建议升级至 3.5.0+")}
    };
    return t;
}

/// 将版本字符串解析为数字段（忽略非数字分隔符，如 9.0.31 / v1.2.5）
QVector<int> parseVersion(const QString &s)
{
    static const QRegularExpression re(QStringLiteral("(\\d+)"));
    QVector<int> parts;
    QRegularExpressionMatchIterator it = re.globalMatch(s);
    while (it.hasNext())
        parts << it.next().captured(1).toInt();
    return parts;
}

/// a < b 的版本比较（缺失段按 0 补齐）
bool versionLess(const QString &a, const QString &b)
{
    const QVector<int> va = parseVersion(a);
    const QVector<int> vb = parseVersion(b);
    const int n = qMax(va.size(), vb.size());
    for (int i = 0; i < n; ++i)
    {
        const int x = i < va.size() ? va.at(i) : 0;
        const int y = i < vb.size() ? vb.at(i) : 0;
        if (x != y)
            return x < y;
    }
    return false;
}

/// 在给定文本中定位“某关键字后紧跟的版本号”，找不到则回退 fallback
QString versionForMarker(const QString &marker, const QString &hayLower, const QString &fallback)
{
    static const QRegularExpression::PatternOptions opt = QRegularExpression::CaseInsensitiveOption;
    const QRegularExpression re(
        QRegularExpression::escape(marker) + QStringLiteral("[^0-9]{0,24}(\\d+(?:\\.\\d+){1,3})"),
        opt);
    const QRegularExpressionMatch m = re.match(hayLower);
    if (m.hasMatch())
        return m.captured(1);
    return fallback;
}

} // namespace

QString vulnHints(const QString &tech, const QString &version, const QByteArray &body)
{
    const QString t = tech.toLower();
    const QString v = version.trimmed();
    const QString bodyLower = QString::fromUtf8(body.left(200 * 1024)).toLower();

    QStringList hints;

    // 1) 技术栈关键字 -> 线索
    for (const VulnMarker &m : vulnTable())
    {
        if (t.contains(m.marker) && !hints.contains(m.hint))
            hints << m.hint;
    }

    // 2) 版本区间 -> 具体 CVE（启发式）；仅当技术栈中命中该产品时才应用
    // 全局版本号（来自响应头等）存在多个产品时语义模糊，故仅在单一产品时作为回退
    int markerCount = 0;
    for (const RangeRule &r : rangeTable())
    {
        if (t.contains(r.marker))
            ++markerCount;
    }
    const bool allowFallback = (markerCount <= 1);

    for (const RangeRule &r : rangeTable())
    {
        if (!t.contains(r.marker))
            continue;

        QString ver = versionForMarker(r.marker, t, allowFallback ? v : QString());
        if (ver.isEmpty())
            ver = versionForMarker(r.marker, bodyLower, QString());
        if (ver.isEmpty())
            continue;

        if (r.major >= 0)
        {
            const QVector<int> parts = parseVersion(ver);
            if (parts.isEmpty() || parts.at(0) != r.major)
                continue;
        }
        if (versionLess(ver, r.below))
            hints << r.hint.arg(ver);
    }

    return hints.join(QStringLiteral("\n"));
}

} // namespace vulndb
} // namespace src