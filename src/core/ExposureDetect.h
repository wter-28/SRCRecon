#pragma once

#include <QByteArray>
#include <QString>
#include <QStringList>

namespace src {
namespace exposure {

/// 返回待探测的敏感路径清单（相对路径，均以 / 开头）。
/// 覆盖 Swagger / OpenAPI 文档、Spring Actuator、Druid 监控页以及 .git/.env 等敏感文件。
QStringList apiDocPaths();

/// 解析 Swagger 2.0 / OpenAPI 3 文档（仅支持 JSON）。
/// 返回形如 "METHOD <绝对URL>" 的接口列表，URL 已按 baseUrl 规范化；
/// title / version 用于回传文档标题与版本（可为 nullptr）。
QStringList parseOpenApi(const QByteArray &body, const QString &baseUrl,
                         QString *title, QString *version);

/// 从 HTML 正文中提取 <form action method> 与其内部 <input name>，
/// 返回形如 "METHOD action [param1,param2,...]" 的字符串列表。
QStringList parseHtmlForms(const QByteArray &body, const QString &baseUrl);

/// 从 .env 正文中提取敏感键名（PASSWORD / KEY / TOKEN / SECRET / DB_ 等）。
QStringList parseEnvSecrets(const QByteArray &body);

/// 依据路径、状态码与正文判定风险说明（中文）。
QString judgeExposure(const QString &path, int code, const QByteArray &body);

} // namespace exposure
} // namespace src