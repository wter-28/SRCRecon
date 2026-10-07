#pragma once

#include "modules/IReconModule.h"

namespace src {

/// TCP 端口扫描：支持常见端口 / 端口段 / 自定义列表，附带服务与 Banner 识别
class PortScanModule : public IReconModule {
public:
    QString id() const override { return QStringLiteral("port"); }
    QString displayName() const override { return QStringLiteral("端口与服务扫描"); }
    void run(ModuleContext &ctx) override;

    /// 解析端口表达式："common" / "1-1024" / "80,443,8000-8100"
    static QVector<int> parsePortSpec(const QString &spec);
};

} // namespace src
