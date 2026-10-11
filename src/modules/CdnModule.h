#pragma once

#include "modules/IReconModule.h"

namespace src {

class ReconState;

/// CDN / WAF 识别：结合 CNAME 链、响应头与源站探测判定目标是否前置 CDN，
/// 并聚合「IP -> 虚拟主机」资产关系。命中 CDN 的主机会被后续端口扫描跳过。
class CdnModule : public IReconModule
{
public:
    QString id() const override { return QStringLiteral("cdn"); }
    QString displayName() const override { return QStringLiteral("CDN / WAF 识别与资产聚合"); }
    void run(ModuleContext &ctx) override;

    /// 依据共享状态生成「IP -> 虚拟主机 / 端口」聚合记录，供界面展示
    static CdnRecordList buildAggregation(ReconState &state);
};

} // namespace src