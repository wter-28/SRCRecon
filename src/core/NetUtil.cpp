#include "core/NetUtil.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QHash>
#include <QHostAddress>
#include <QHostInfo>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSslError>
#include <QTcpSocket>
#include <QTimer>
#include <QUrl>

namespace src {

namespace {
const char *kUserAgent =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0 Safari/537.36 SRCRecon/1.0";
} // namespace

QString HttpResponse::contentType() const { return headers.value(QStringLiteral("content-type")); }

qint64 HttpResponse::contentLength() const
{
    if (headers.contains(QStringLiteral("content-length")))
        return headers.value(QStringLiteral("content-length")).toLongLong();
    return body.size();
}

bool HttpResponse::isHtml() const
{
    const QString ct = contentType().toLower();
    return ct.contains(QStringLiteral("html")) || ct.contains(QStringLiteral("xml"))
        || ct.contains(QStringLiteral("json")) || ct.isEmpty();
}

HttpResponse NetUtil::httpRequest(const QString &url, int timeoutMs, const QString &method,
                                  const QByteArray &body,
                                  const QMap<QString, QString> &extraHeaders)
{
    HttpResponse res;
    QElapsedTimer elapsed;
    elapsed.start();

    QNetworkAccessManager nam;
    nam.setRedirectPolicy(QNetworkRequest::NoLessSafeRedirectPolicy);

    QNetworkRequest req{QUrl(url)};
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                     QNetworkRequest::NoLessSafeRedirectPolicy);
    req.setMaximumRedirectsAllowed(6);
    req.setTransferTimeout(timeoutMs);
    req.setHeader(QNetworkRequest::UserAgentHeader, QString::fromLatin1(kUserAgent));
    req.setRawHeader("Accept", "*/*");
    req.setRawHeader("Accept-Encoding", "identity");
    req.setRawHeader("Connection", "close");
    for (auto it = extraHeaders.constBegin(); it != extraHeaders.constEnd(); ++it)
        req.setRawHeader(it.key().toUtf8(), it.value().toUtf8());

    const QString m = method.toUpper();
    QNetworkReply *reply = nullptr;
    if (m == QLatin1String("GET"))       reply = nam.get(req);
    else if (m == QLatin1String("HEAD")) reply = nam.head(req);
    else if (m == QLatin1String("POST")) reply = nam.post(req, body);
    else if (m == QLatin1String("PUT"))  reply = nam.put(req, body);
    else                                 reply = nam.sendCustomRequest(req, m.toUtf8(), body);

    QEventLoop loop;
    QTimer timer;
    timer.setSingleShot(true);
    bool timedOut = false;

    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    QObject::connect(reply, &QNetworkReply::sslErrors, reply,
                     [reply](const QList<QSslError> &) { reply->ignoreSslErrors(); });
    QObject::connect(&timer, &QTimer::timeout, &loop, [&] {
        timedOut = true;
        reply->abort();
    });

    timer.start(timeoutMs + 500);
    loop.exec();

    res.statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    res.finalUrl = reply->url().toString();
    res.body = reply->readAll();
    res.errorString = timedOut ? QStringLiteral("请求超时: %1").arg(url) : reply->errorString();
    res.ok = !timedOut && reply->error() == QNetworkReply::NoError;

    const auto pairs = reply->rawHeaderPairs();
    for (const auto &p : pairs)
        res.headers.insert(QString::fromUtf8(p.first).toLower(), QString::fromUtf8(p.second));

    res.elapsedMs = elapsed.elapsed();
    reply->deleteLater();
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    return res;
}

QStringList NetUtil::resolveHost(const QString &host)
{
    QStringList out;
    if (host.isEmpty())
        return out;

    QHostAddress direct;
    if (direct.setAddress(host)) {
        out << host;
        return out;
    }

    const QHostInfo info = QHostInfo::fromName(host);
    if (info.error() != QHostInfo::NoError)
        return out;

    const auto addrs = info.addresses();
    for (const QHostAddress &a : addrs) {
        const QString s = a.toString();
        if (!out.contains(s))
            out << s;
    }
    return out;
}

QString NetUtil::resolveFirst(const QString &host)
{
    const QStringList all = resolveHost(host);
    return all.isEmpty() ? QString() : all.first();
}

QString NetUtil::whoisServerFor(const QString &domain)
{
    static const QHash<QString, QString> m = {
        {QStringLiteral("com"),     QStringLiteral("whois.verisign-grs.com")},
        {QStringLiteral("net"),     QStringLiteral("whois.verisign-grs.com")},
        {QStringLiteral("org"),     QStringLiteral("whois.pir.org")},
        {QStringLiteral("cn"),      QStringLiteral("whois.cnnic.cn")},
        {QStringLiteral("com.cn"),  QStringLiteral("whois.cnnic.cn")},
        {QStringLiteral("net.cn"),  QStringLiteral("whois.cnnic.cn")},
        {QStringLiteral("org.cn"),  QStringLiteral("whois.cnnic.cn")},
        {QStringLiteral("gov.cn"),  QStringLiteral("whois.cnnic.cn")},
        {QStringLiteral("io"),      QStringLiteral("whois.nic.io")},
        {QStringLiteral("me"),      QStringLiteral("whois.nic.me")},
        {QStringLiteral("cc"),      QStringLiteral("ccwhois.verisign-grs.com")},
        {QStringLiteral("info"),    QStringLiteral("whois.afilias.net")},
        {QStringLiteral("biz"),     QStringLiteral("whois.biz")},
        {QStringLiteral("top"),     QStringLiteral("whois.nic.top")},
        {QStringLiteral("xyz"),     QStringLiteral("whois.nic.xyz")},
        {QStringLiteral("tech"),    QStringLiteral("whois.nic.tech")},
        {QStringLiteral("online"),  QStringLiteral("whois.nic.online")},
        {QStringLiteral("site"),    QStringLiteral("whois.nic.site")},
        {QStringLiteral("store"),   QStringLiteral("whois.nic.store")},
        {QStringLiteral("app"),     QStringLiteral("whois.nic.google")},
        {QStringLiteral("dev"),     QStringLiteral("whois.nic.google")},
        {QStringLiteral("co"),      QStringLiteral("whois.nic.co")},
        {QStringLiteral("tv"),      QStringLiteral("whois.nic.tv")},
        {QStringLiteral("jp"),      QStringLiteral("whois.jprs.jp")},
        {QStringLiteral("kr"),      QStringLiteral("whois.kr")},
        {QStringLiteral("hk"),      QStringLiteral("whois.hkirc.hk")},
        {QStringLiteral("tw"),      QStringLiteral("whois.twnic.net.tw")},
    };

    const QStringList parts = domain.toLower().split(QLatin1Char('.'), Qt::SkipEmptyParts);
    if (parts.size() >= 2) {
        const QString two = parts.mid(parts.size() - 2).join(QLatin1Char('.'));
        if (m.contains(two))
            return m.value(two);
    }
    if (!parts.isEmpty() && m.contains(parts.last()))
        return m.value(parts.last());
    return QStringLiteral("whois.iana.org");
}

QString NetUtil::whoisQuery(const QString &server, const QString &query, int timeoutMs)
{
    QTcpSocket sock;
    sock.connectToHost(server, 43);
    if (!sock.waitForConnected(timeoutMs))
        return QString();

    sock.write(query.toUtf8() + "\r\n");
    sock.flush();

    QByteArray data;
    while (sock.waitForReadyRead(timeoutMs)) {
        data += sock.readAll();
        if (data.size() > 256 * 1024)
            break;
    }
    data += sock.readAll();
    sock.abort();
    return QString::fromUtf8(data);
}

bool NetUtil::tcpConnect(const QString &host, int port, int timeoutMs, QString *banner,
                         const QByteArray &probe)
{
    QTcpSocket sock;
    sock.connectToHost(host, static_cast<quint16>(port));
    if (!sock.waitForConnected(timeoutMs)) {
        sock.abort();
        return false;
    }

    if (banner) {
        QString text;
        if (!probe.isEmpty()) {
            sock.write(probe);
            sock.flush();
        }
        const int waitMs = qMin(1200, timeoutMs);
        if (sock.waitForReadyRead(waitMs))
            text = QString::fromLatin1(sock.read(1024));
        else if (sock.bytesAvailable() > 0)
            text = QString::fromLatin1(sock.read(1024));
        *banner = text.simplified().left(300);
    }

    sock.abort();
    return true;
}

QString NetUtil::urlEncode(const QString &s)
{
    return QString::fromLatin1(QUrl::toPercentEncoding(s));
}

QString NetUtil::urlDecode(const QString &s)
{
    return QUrl::fromPercentEncoding(s.toUtf8());
}

} // namespace src
