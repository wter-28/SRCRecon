#pragma once

#include "modules/IReconModule.h"

namespace src {

/// 目录 / 敏感路径探测：内置字典并发请求，识别状态码、长度与特征
class DirScanModule : public IReconModule {
public:
    QString id() const override { return QStringLiteral("dir"); }
    QString displayName() const override { return QStringLiteral("目录/敏感路径探测"); }
    void run(ModuleContext &ctx) override;
};

} // namespace src
