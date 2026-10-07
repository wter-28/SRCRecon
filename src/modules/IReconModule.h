#pragma once

#include <QString>
#include <functional>
#include <atomic>

#include "core/Types.h"
#include "core/EngineOptions.h"

class QThreadPool;

namespace src {

/// 模块运行时上下文：提供线程池、取消标志以及向引擎回传结果的回调。
/// 所有回调都是线程安全的（内部通过 Qt 队列信号投递到主线程）。
struct ModuleContext {
    const EngineOptions *opt = nullptr;
    QThreadPool *pool = nullptr;
    std::atomic<bool> *cancelFlag = nullptr;

    std::function<void(const QString &level, const QString &text)> log;
    std::function<void(int done, int total)> progress;

    std::function<void(const DomainAssetList &)>    addSubdomains;
    std::function<void(const WhoisInfo &)>          addWhois;
    std::function<void(const IcpInfo &)>            addIcp;
    std::function<void(const IpLocation &)>         addIpLocation;
    std::function<void(const PortResultList &)>     addPorts;
    std::function<void(const WebFingerprintList &)> addFingerprints;
    std::function<void(const DirRecordList &)>      addDirs;
    std::function<void(const UrlRecordList &)>      addUrls;

    bool isCancelled() const { return cancelFlag && cancelFlag->load(); }

    void info(const QString &t) const  { if (log) log(QStringLiteral("info"), t); }
    void ok(const QString &t) const    { if (log) log(QStringLiteral("ok"), t); }
    void warn(const QString &t) const  { if (log) log(QStringLiteral("warn"), t); }
    void error(const QString &t) const { if (log) log(QStringLiteral("error"), t); }
};

/// 信息收集模块统一接口
class IReconModule {
public:
    virtual ~IReconModule() = default;

    /// 模块唯一标识（英文）
    virtual QString id() const = 0;
    /// 界面显示名（中文）
    virtual QString displayName() const = 0;
    /// 执行收集，结果通过 ctx 回调回传
    virtual void run(ModuleContext &ctx) = 0;
};

} // namespace src
