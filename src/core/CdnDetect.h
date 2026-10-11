#pragma once

#include <QString>
#include <QStringList>

#include "core/NetUtil.h"

namespace src {
namespace cdn {

/// CDN / WAF 判定结果
struct Verdict
{
    bool        hit = false;    // 是否命中 CDN
    QString     vendor;         // 厂商
    QString     category;       // 类别：CDN / WAF / 云 WAF
    QStringList cnameChain;     // CNAME 链
    QString     reason;         // 判定依据
};

/// 通过 DNS over HTTPS（Google DNS JSON 接口）查询 CNAME 链，最多跟随 5 跳
QStringList lookupCnameChain(const QString &host, int timeoutMs);

/// 依据 CNAME 链匹配 CDN 厂商（未命中返回空字符串）
QString matchCnameVendor(const QStringList &chain);

/// 依据响应头 / 服务端特征判定 CDN
Verdict detectByHeaders(const HttpResponse &res);

/// 识别 WAF / 云 WAF（返回厂商，未识别返回空字符串）
QString detectWaf(const HttpResponse &res);

/// 依据技术栈 / 版本号 / 页面内容给出已知漏洞线索（best-effort，仅供排查方向）
QString cveHints(const QString &techJoined, const QByteArray &body);

/// 组合出 CDN 判定依据文本，便于展示
QString joinReason(const QStringList &parts);

} // namespace cdn
} // namespace src