#pragma once

#include "core/Types.h"

/// 演示模式下的内置数据，便于在无网络环境下验证完整流程与界面。
namespace src {
namespace demo {

DomainAssetList    subdomains(const QString &domain);
WhoisInfo          whois(const QString &domain);
IcpInfo            icp(const QString &domain);
IpLocation         ipLocation(const QString &ip);
PortResultList     ports(const QString &host);
WebFingerprintList fingerprints(const QString &baseUrl);
DirRecordList      dirs(const QString &baseUrl);
UrlRecordList      urls(const QString &baseUrl);

} // namespace demo
} // namespace src
