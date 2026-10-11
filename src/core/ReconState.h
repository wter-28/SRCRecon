#pragma once

#include <QMutex>
#include <QMutexLocker>
#include <QMap>
#include <QString>
#include <QStringList>
#include <QVector>

#include "core/Types.h"

namespace src {

/// 跨模块共享的资产状态。所有模块通过 ModuleContext::state 读写，
/// 用于把前序模块的发现（子域名、端口、CDN 判定、存活 Web 服务）
/// 串联给后续模块，避免每个模块只扫描根目标。
///
/// 所有公开方法均为线程安全。
class ReconState
{
public:
    /// 单个主机的资产画像
    struct HostEntry
    {
        QString     host;
        QString     ip;
        QString     source;
        bool        cdn = false;   // 是否命中 CDN
        QString     cdnVendor;     // CDN / WAF 厂商
        QStringList cnameChain;
    };

    // ---------------- 主机 ----------------

    /// 记录一个存活主机（host -> ip）
    void addHost(const QString &host, const QString &ip, const QString &source)
    {
        if (host.isEmpty() || ip.isEmpty())
            return;

        QMutexLocker locker(&m_mtx);

        HostEntry &e = m_hosts[host];
        e.host   = host;
        e.ip     = ip;
        e.source = source.isEmpty() ? e.source : source;

        QStringList &vhosts = m_ipHosts[ip];
        if (!vhosts.contains(host))
            vhosts << host;
    }

    /// 返回全部主机快照
    QVector<HostEntry> hosts() const
    {
        QMutexLocker locker(&m_mtx);
        QVector<HostEntry> out;
        out.reserve(m_hosts.size());
        for (auto it = m_hosts.constBegin(); it != m_hosts.constEnd(); ++it)
            out << it.value();
        return out;
    }

    /// 返回同一 IP 上绑定的全部主机名（虚拟主机聚合）
    QStringList hostsOfIp(const QString &ip) const
    {
        QMutexLocker locker(&m_mtx);
        return m_ipHosts.value(ip);
    }

    /// 返回全部解析到的 IP
    QStringList allIps() const
    {
        QMutexLocker locker(&m_mtx);
        return m_ipHosts.keys();
    }

    /// 查询主机解析 IP
    QString ipOfHost(const QString &host) const
    {
        QMutexLocker locker(&m_mtx);
        return m_hosts.value(host).ip;
    }

    // ---------------- CDN / WAF ----------------

    /// 标记主机的 CDN 判定结果
    void setCdn(const QString &host, bool cdn, const QString &vendor,
                const QStringList &cnameChain)
    {
        QMutexLocker locker(&m_mtx);
        HostEntry &e = m_hosts[host];
        e.host = host;
        e.cdn = cdn;
        e.cdnVendor = vendor;
        e.cnameChain = cnameChain;
    }

    /// 查询主机是否为 CDN（可返回厂商）
    bool isCdn(const QString &host, QString *vendor = nullptr) const
    {
        QMutexLocker locker(&m_mtx);
        const auto it = m_hosts.constFind(host);
        if (it == m_hosts.constEnd() || !it.value().cdn)
            return false;
        if (vendor)
            *vendor = it.value().cdnVendor;
        return true;
    }

    /// 查询某 IP 是否被判定为 CDN 边缘（同一 IP 上任一主机命中即可）
    bool isCdnIp(const QString &ip, QString *vendor = nullptr) const
    {
        QMutexLocker locker(&m_mtx);
        const QStringList vhosts = m_ipHosts.value(ip);
        for (const QString &h : vhosts) {
            const auto it = m_hosts.constFind(h);
            if (it != m_hosts.constEnd() && it.value().cdn) {
                if (vendor)
                    *vendor = it.value().cdnVendor;
                return true;
            }
        }
        return false;
    }

    void addCdnRecord(const CdnRecord &r)
    {
        QMutexLocker locker(&m_mtx);
        m_cdn << r;
    }

    CdnRecordList cdnRecords() const
    {
        QMutexLocker locker(&m_mtx);
        return m_cdn;
    }

    // ---------------- 端口 ----------------

    /// 记录某 IP 上探测到的开放端口
    void addPort(const QString &ip, int port)
    {
        QMutexLocker locker(&m_mtx);
        QVector<int> &v = m_ports[ip];
        if (!v.contains(port))
            v << port;
    }

    QVector<int> portsOf(const QString &ip) const
    {
        QMutexLocker locker(&m_mtx);
        return m_ports.value(ip);
    }

    // ---------------- Web 目标 ----------------

    /// 登记一个待探测的 Web 基础地址
    void addWebTarget(const QString &baseUrl)
    {
        if (baseUrl.isEmpty())
            return;
        QMutexLocker locker(&m_mtx);
        if (!m_webTargets.contains(baseUrl))
            m_webTargets << baseUrl;
    }

    QStringList webTargets() const
    {
        QMutexLocker locker(&m_mtx);
        return m_webTargets;
    }

    /// 登记一个已确认存活的 Web 服务
    void addAliveWeb(const QString &baseUrl)
    {
        if (baseUrl.isEmpty())
            return;
        QMutexLocker locker(&m_mtx);
        if (!m_aliveWeb.contains(baseUrl))
            m_aliveWeb << baseUrl;
    }

    QStringList aliveWeb() const
    {
        QMutexLocker locker(&m_mtx);
        return m_aliveWeb;
    }

    // ---------------- 源站候选 ----------------

    /// 记录一个非 CDN 的候选源站 IP 及其证据
    void addOriginCandidate(const QString &ip, const QString &evidence)
    {
        if (ip.isEmpty())
            return;
        QMutexLocker locker(&m_mtx);
        m_origin[ip] = evidence;
    }

    QMap<QString, QString> originCandidates() const
    {
        QMutexLocker locker(&m_mtx);
        return m_origin;
    }

private:
    mutable QMutex m_mtx;

    QMap<QString, HostEntry>     m_hosts;      // host -> 画像
    QMap<QString, QStringList>   m_ipHosts;    // ip -> 主机名列表（虚拟主机聚合）
    QMap<QString, QVector<int>>  m_ports;      // ip -> 开放端口
    QStringList                  m_webTargets; // 待探测 Web 地址
    QStringList                  m_aliveWeb;   // 已存活 Web 地址
    QVector<CdnRecord>           m_cdn;        // CDN 判定记录
    QMap<QString, QString>       m_origin;     // 源站候选 IP -> 证据
};

} // namespace src