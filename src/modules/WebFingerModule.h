#pragma once

#include "modules/IReconModule.h"

namespace src {

/// Web 指纹识别：抓取首页/常见入口，识别标题、Server、中间件、CMS、框架
class WebFingerModule : public IReconModule {
public:
    QString id() const override { return QStringLiteral("finger"); }
    QString displayName() const override { return QStringLiteral("Web 指纹识别"); }
    void run(ModuleContext &ctx) override;
};

} // namespace src
