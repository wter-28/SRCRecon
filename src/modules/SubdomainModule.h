#pragma once

#include "modules/IReconModule.h"

namespace src {

/// 子域名枚举：证书透明日志(crt.sh) + 字典 DNS 爆破，含泛解析检测
class SubdomainModule : public IReconModule {
public:
    QString id() const override { return QStringLiteral("subdomain"); }
    QString displayName() const override { return QStringLiteral("子域名枚举"); }
    void run(ModuleContext &ctx) override;
};

} // namespace src
