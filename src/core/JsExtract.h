#pragma once

#include <QByteArray>
#include <QString>
#include <QStringList>

namespace src {
namespace jsx {

/// 从 JS / HTML 正文中提取 API 接口路径与绝对地址（相较普通链接更聚焦接口）
/// baseUrl 用于把相对路径补全为绝对地址
QStringList extractEndpoints(const QByteArray &body, const QString &baseUrl);

/// 从 JS / HTML 正文中提取疑似凭据、密钥、令牌等敏感信息（截断展示）
QStringList extractSecrets(const QByteArray &body);

} // namespace jsx
} // namespace src