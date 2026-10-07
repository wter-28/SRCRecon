#pragma once

#include <QString>

namespace src {

struct EngineOptions;

namespace settings {

/// 从注册表/配置文件中读取上次使用的参数
void load(EngineOptions &opt);
/// 保存参数
void save(const EngineOptions &opt);

QString icpApiUrl();
void setIcpApiUrl(const QString &url);

} // namespace settings
} // namespace src
