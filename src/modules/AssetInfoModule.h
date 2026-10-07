#pragma once

#include "modules/IReconModule.h"

namespace src {

/// 基础资产信息：Whois 注册信息、ICP 备案、IP 归属地
class AssetInfoModule : public IReconModule {
public:
    QString id() const override { return QStringLiteral("asset"); }
    QString displayName() const override { return QStringLiteral("基础资产信息"); }
    void run(ModuleContext &ctx) override;
};

} // namespace src
