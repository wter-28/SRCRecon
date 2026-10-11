#include "core/CdnIpRange.h"

#include <QVector>

namespace src {
namespace cdn {

namespace {

/// 解析后的网段条目：网络地址（主机序）+ 前缀长度 + 厂商
struct Range
{
    quint32 net = 0;
    int     prefix = 0;
    QString vendor;
};

/// 原始网段文本 -> 厂商。该表人工维护，可能滞后于厂商实际调整。
struct RawRange
{
    const char *cidr;
    const char *vendor;
};

const RawRange *rawTable(int *count)
{
    // IPv4 网段表：Cloudflare / Fastly / AWS CloudFront / Akamai / 阿里云 / 腾讯云
    static const RawRange t[] = {
        // Cloudflare
        {"173.245.48.0/20", "Cloudflare"},
        {"103.21.244.0/22", "Cloudflare"},
        {"103.22.200.0/22", "Cloudflare"},
        {"103.31.4.0/22", "Cloudflare"},
        {"141.101.64.0/18", "Cloudflare"},
        {"108.162.192.0/18", "Cloudflare"},
        {"190.93.240.0/20", "Cloudflare"},
        {"188.114.96.0/20", "Cloudflare"},
        {"197.234.240.0/22", "Cloudflare"},
        {"198.41.128.0/17", "Cloudflare"},
        {"162.158.0.0/15", "Cloudflare"},
        {"104.16.0.0/13", "Cloudflare"},
        {"104.24.0.0/14", "Cloudflare"},
        {"172.64.0.0/13", "Cloudflare"},
        {"131.0.72.0/22", "Cloudflare"},
        // Fastly
        {"151.101.0.0/16", "Fastly"},
        {"199.232.0.0/16", "Fastly"},
        {"146.75.0.0/16", "Fastly"},
        {"23.235.32.0/20", "Fastly"},
        {"43.249.72.0/22", "Fastly"},
        {"104.156.80.0/20", "Fastly"},
        {"157.52.64.0/18", "Fastly"},
        {"167.82.0.0/17", "Fastly"},
        {"167.82.128.0/17", "Fastly"},
        // AWS CloudFront
        {"13.32.0.0/15", "AWS CloudFront"},
        {"13.35.0.0/16", "AWS CloudFront"},
        {"13.113.196.0/22", "AWS CloudFront"},
        {"13.113.203.0/24", "AWS CloudFront"},
        {"13.124.199.0/24", "AWS CloudFront"},
        {"13.224.0.0/14", "AWS CloudFront"},
        {"13.228.69.0/24", "AWS CloudFront"},
        {"13.249.0.0/16", "AWS CloudFront"},
        {"18.238.0.0/15", "AWS CloudFront"},
        {"18.244.0.0/15", "AWS CloudFront"},
        {"52.46.0.0/18", "AWS CloudFront"},
        {"52.82.128.0/19", "AWS CloudFront"},
        {"52.84.0.0/15", "AWS CloudFront"},
        {"54.182.0.0/16", "AWS CloudFront"},
        {"54.192.0.0/16", "AWS CloudFront"},
        {"54.230.0.0/16", "AWS CloudFront"},
        {"54.239.128.0/18", "AWS CloudFront"},
        {"54.240.128.0/18", "AWS CloudFront"},
        {"99.84.0.0/16", "AWS CloudFront"},
        {"99.86.0.0/16", "AWS CloudFront"},
        {"130.176.0.0/16", "AWS CloudFront"},
        {"143.204.0.0/16", "AWS CloudFront"},
        {"144.220.0.0/16", "AWS CloudFront"},
        {"204.246.164.0/22", "AWS CloudFront"},
        {"204.246.168.0/22", "AWS CloudFront"},
        {"204.246.172.0/24", "AWS CloudFront"},
        {"204.246.174.0/23", "AWS CloudFront"},
        {"204.246.176.0/20", "AWS CloudFront"},
        {"205.251.192.0/19", "AWS CloudFront"},
        {"205.251.249.0/24", "AWS CloudFront"},
        {"205.251.250.0/23", "AWS CloudFront"},
        {"205.251.252.0/23", "AWS CloudFront"},
        {"205.251.254.0/24", "AWS CloudFront"},
        {"216.137.32.0/19", "AWS CloudFront"},
        // Akamai（代表性网段）
        {"2.16.0.0/13", "Akamai"},
        {"23.32.0.0/11", "Akamai"},
        {"23.64.0.0/13", "Akamai"},
        {"23.72.0.0/13", "Akamai"},
        {"23.192.0.0/11", "Akamai"},
        {"23.200.0.0/13", "Akamai"},
        {"23.208.0.0/12", "Akamai"},
        {"72.246.0.0/15", "Akamai"},
        {"88.221.0.0/16", "Akamai"},
        {"95.100.0.0/16", "Akamai"},
        {"96.6.0.0/15", "Akamai"},
        {"96.16.0.0/15", "Akamai"},
        {"104.64.0.0/10", "Akamai"},
        {"184.24.0.0/13", "Akamai"},
        {"184.50.0.0/15", "Akamai"},
        {"184.84.0.0/14", "Akamai"},
        // 阿里云 CDN（代表性网段）
        {"8.209.0.0/16", "阿里云 CDN"},
        {"47.74.0.0/15", "阿里云 CDN"},
        {"106.11.0.0/16", "阿里云 CDN"},
        {"106.14.0.0/16", "阿里云 CDN"},
        {"106.15.0.0/16", "阿里云 CDN"},
        {"112.124.0.0/16", "阿里云 CDN"},
        {"116.62.0.0/16", "阿里云 CDN"},
        {"118.178.0.0/16", "阿里云 CDN"},
        {"120.24.0.0/16", "阿里云 CDN"},
        {"121.40.0.0/16", "阿里云 CDN"},
        {"121.196.0.0/16", "阿里云 CDN"},
        {"139.129.0.0/16", "阿里云 CDN"},
        {"139.196.0.0/16", "阿里云 CDN"},
        // 腾讯云 CDN（代表性网段）
        {"1.12.0.0/16", "腾讯云 CDN"},
        {"43.128.0.0/12", "腾讯云 CDN"},
        {"49.51.0.0/16", "腾讯云 CDN"},
        {"101.32.0.0/16", "腾讯云 CDN"},
        {"119.28.0.0/16", "腾讯云 CDN"},
        {"129.226.0.0/16", "腾讯云 CDN"},
        {"150.109.0.0/16", "腾讯云 CDN"},
        {"162.62.0.0/16", "腾讯云 CDN"}
    };
    *count = int(sizeof(t) / sizeof(t[0]));
    return t;
}

/// 解析 IPv4 点分十进制为 32 位整数（主机序）
bool parseIpv4(const QString &ip, quint32 *out)
{
    const QStringList parts = ip.trimmed().split(QLatin1Char('.'));
    if (parts.size() != 4)
        return false;

    quint32 v = 0;
    for (const QString &p : parts)
    {
        bool ok = false;
        const int n = p.toInt(&ok);
        if (!ok || n < 0 || n > 255)
            return false;
        v = (v << 8) | quint32(n);
    }
    *out = v;
    return true;
}

/// 构建并缓存解析后的网段表
const QVector<Range> &parsedTable()
{
    static const QVector<Range> table = []() {
        QVector<Range> out;
        int count = 0;
        const RawRange *raw = rawTable(&count);
        out.reserve(count);
        for (int i = 0; i < count; ++i)
        {
            const QString s = QString::fromLatin1(raw[i].cidr);
            const int slash = s.indexOf(QLatin1Char('/'));
            if (slash <= 0)
                continue;

            quint32 net = 0;
            if (!parseIpv4(s.left(slash), &net))
                continue;

            bool ok = false;
            const int prefix = s.mid(slash + 1).toInt(&ok);
            if (!ok || prefix < 0 || prefix > 32)
                continue;

            Range r;
            r.net    = net;
            r.prefix = prefix;
            r.vendor = QString::fromLatin1(raw[i].vendor);
            out << r;
        }
        return out;
    }();
    return table;
}

} // namespace

bool matchCdnRange(const QString &ip, QString *vendor)
{
    quint32 addr = 0;
    if (!parseIpv4(ip, &addr))
        return false;

    for (const Range &r : parsedTable())
    {
        const quint32 mask = r.prefix == 0 ? quint32(0)
                                           : (~quint32(0) << (32 - r.prefix));
        if ((addr & mask) == (r.net & mask))
        {
            if (vendor)
                *vendor = r.vendor;
            return true;
        }
    }
    return false;
}

} // namespace cdn
} // namespace src