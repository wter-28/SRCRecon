#pragma once

#include "core/ReconState.h"
#include "core/Types.h"

namespace src {

/// 资产优先级排序：把各模块的零散发现合并为带「危险级别 + 数值评分」的资产总览。
/// 全部为无状态静态辅助函数，供引擎在流水线末尾统一调用。
class AssetRank
{
public:
    /// 由目录 / 敏感路径记录推导危险级别（高 / 中 / 低 / 信息）
    static QString severityOf(const DirRecord &r);
    /// 由 Web 指纹记录推导危险级别
    static QString severityOf(const WebFingerprint &f);
    /// 由接口 / 暴露面记录推导危险级别
    static QString severityOf(const ApiEndpoint &e);
    /// 由端口记录推导危险级别
    static QString severityOf(const PortResult &p);

    /// 依据危险级别与类别计算数值评分（高=90 / 中=60 / 低=30 / 信息=5 + 类别加权）
    static int scoreOf(const QString &severity, const QString &category);

    /// 合并所有模块发现，按 (ip|host, 类别, 值) 去重后按评分降序返回资产总览
    static AssetSummaryList build(const ReconState &state, const PortResultList &ports,
                                  const WebFingerprintList &fps, const DirRecordList &dirs,
                                  const ApiEndpointList &eps, const CdnRecordList &cdn);
};

} // namespace src