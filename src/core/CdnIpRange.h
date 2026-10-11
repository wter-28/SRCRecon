#pragma once

#include <QString>

namespace src {
namespace cdn {

/// 判断某个 IPv4 是否落在已知 CDN 边缘网段内。
/// 命中时返回 true，并可通过 vendor 输出对应厂商名（如 Cloudflare、Fastly 等）。
///
/// 说明：内置的 CIDR 网段表为人工维护，可能滞后于厂商实际的网段调整，
/// 仅作为辅助证据与置信度加权使用，不应单独作为唯一判定依据。
bool matchCdnRange(const QString &ip, QString *vendor = nullptr);

} // namespace cdn
} // namespace src