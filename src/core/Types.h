#pragma once

#include <QString>
#include <QStringList>
#include <QVector>
#include <QMetaType>

namespace src {

/// 子域名 / DNS 资产
struct DomainAsset {
    QString host;    // 主机名
    QString ip;      // 解析到的 IP（可能为空）
    QString source;  // 来源：主域名 / 字典 / 证书透明日志
};

/// Whois 注册信息
struct WhoisInfo {
    QString domain;
    QString registrar;      // 注册商
    QString registrant;     // 注册人/单位
    QString creationDate;   // 注册时间
    QString expiryDate;     // 到期时间
    QString updatedDate;    // 更新时间
    QString nameServers;    // DNS 服务器
    QString status;         // 域名状态
    QString raw;            // 原始返回（截断保存）
};

/// ICP 备案信息
struct IcpInfo {
    QString domain;
    QString number;     // 备案号
    QString company;    // 主办单位
    QString nature;     // 单位性质
    QString siteName;   // 网站名称
    QString auditDate;  // 审核通过时间
};

/// IP 归属地
struct IpLocation {
    QString ip;
    QString country;
    QString region;
    QString city;
    QString isp;
    QString org;
    QString asn;
    QString timezone;
};

/// 端口扫描结果
struct PortResult {
    QString host;
    int port = 0;
    QString proto = QStringLiteral("tcp");
    QString service;  // 服务猜测
    QString banner;   // 指纹 Banner
};

/// Web 指纹识别结果
struct WebFingerprint {
    QString url;
    int statusCode = 0;
    QString title;
    QString server;
    QString poweredBy;
    QString technologies;  // 逗号分隔的技术栈
    QString extraHeaders;  // 其他关键响应头
};

/// 目录 / 敏感路径探测结果
struct DirRecord {
    QString url;
    int statusCode = 0;
    qint64 length = 0;
    QString contentType;
    QString note;
};

/// URL / 链接收集结果
struct UrlRecord {
    QString url;
    int statusCode = 0;
    QString contentType;
    qint64 length = 0;
    QString source;  // 爬虫页面 / JS文件 / 表单
};

using DomainAssetList    = QVector<DomainAsset>;
using PortResultList     = QVector<PortResult>;
using WebFingerprintList = QVector<WebFingerprint>;
using DirRecordList      = QVector<DirRecord>;
using UrlRecordList      = QVector<UrlRecord>;

/// 根据 HTTP 状态码返回简短中文说明
inline QString statusNote(int code)
{
    if (code <= 0)   return QStringLiteral("无响应");
    if (code < 200)  return QStringLiteral("信息");
    if (code < 300)  return QStringLiteral("成功");
    if (code == 301) return QStringLiteral("永久跳转");
    if (code == 302) return QStringLiteral("临时跳转");
    if (code == 303 || code == 307 || code == 308) return QStringLiteral("跳转");
    if (code == 401) return QStringLiteral("未授权");
    if (code == 403) return QStringLiteral("禁止访问");
    if (code == 404) return QStringLiteral("不存在");
    if (code == 405) return QStringLiteral("方法不允许");
    if (code == 429) return QStringLiteral("请求过多");
    if (code >= 500) return QStringLiteral("服务器错误");
    return QString::number(code);
}

} // namespace src

Q_DECLARE_METATYPE(src::DomainAsset)
Q_DECLARE_METATYPE(src::WhoisInfo)
Q_DECLARE_METATYPE(src::IcpInfo)
Q_DECLARE_METATYPE(src::IpLocation)
Q_DECLARE_METATYPE(src::PortResult)
Q_DECLARE_METATYPE(src::WebFingerprint)
Q_DECLARE_METATYPE(src::DirRecord)
Q_DECLARE_METATYPE(src::UrlRecord)
Q_DECLARE_METATYPE(src::DomainAssetList)
Q_DECLARE_METATYPE(src::PortResultList)
Q_DECLARE_METATYPE(src::WebFingerprintList)
Q_DECLARE_METATYPE(src::DirRecordList)
Q_DECLARE_METATYPE(src::UrlRecordList)
