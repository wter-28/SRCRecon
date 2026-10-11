#pragma once

#include "modules/IReconModule.h"

namespace src {

/// 接口 / 暴露面分析：探测 API 文档、Actuator、敏感文件与表单，
/// 聚合接口清单并给出风险提示，串联爬虫提取到的 JS 接口候选。
class ExposureModule : public IReconModule
{
public:
    QString id() const override { return QStringLiteral("exposure"); }
    QString displayName() const override { return QStringLiteral("接口/暴露面分析"); }
    void run(ModuleContext &ctx) override;
};

} // namespace src