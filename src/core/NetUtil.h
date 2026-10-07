#pragma once

#include <QString>
#include <QStringList>
#include <QByteArray>
#include <QMap>

namespace src {

/// 阻塞式 HTTP 响应
struct HttpResponse {
    bool    ok = false;
    int     statusCode = 0;
    QByteArray body;
    QMap<QString, QString> headers;  // 键统一为小写
    QString errorString;
    QString finalUrl;
    qint64  elapsedMs = 0;

    QString header(const QString &key) const { return headers.value(key.toLower()); }
    QString contentType() const;
    qint64  contentLength() const;
    bool    isHtml() const;
};

/// 阻塞式网络工具集。所有方法均为同步调用，可安全地在工作线程中使用。
class NetUtil {
public:
    static HttpResponse httpRequest(const QString &url,
                                    int timeoutMs = 8000,
                                    const QString &method = QStringLiteral("GET"),
                                    const QByteArray &body = QByteArray(),
                                    const QMap<QString, QString> &extraHeaders
                                        = QMap<QString, QString>());

    /// 解析主机名，返回全部 IPv4/IPv6 地址
    static QStringList resolveHost(const QString &host);
    /// 解析主机名，返回第一个地址（失败返回空）
    static QString resolveFirst(const QString &host);

    /// 根据域名后缀推断 whois 服务器
    static QString whoisServerFor(const QString &domain);
    /// 向 whois 服务器发起 43 端口查询
    static QString whoisQuery(const QString &server, const QString &query, int timeoutMs = 8000);

    /// TCP 连接探测；banner 可返回抓取到的服务指纹
    static bool tcpConnect(const QString &host, int port, int timeoutMs,
                           QString *banner = nullptr,
                           const QByteArray &probe = QByteArray());

    static QString urlEncode(const QString &s);
    static QString urlDecode(const QString &s);
};

} // namespace src
