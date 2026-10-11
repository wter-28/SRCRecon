#pragma once

#include <QObject>
#include <QThreadPool>
#include <QVector>

#include <atomic>
#include <memory>
#include <thread>

#include "core/EngineOptions.h"
#include "core/Types.h"
#include "modules/IReconModule.h"

namespace src {

/// 信息收集调度引擎：负责参数校验、模块编排、线程池调度、进度与取消
class ReconEngine : public QObject {
    Q_OBJECT

public:
    explicit ReconEngine(QObject *parent = nullptr);
    ~ReconEngine() override;

    bool isRunning() const { return m_running.load(); }

    /// 启动一次信息收集任务（异步，结果通过信号返回）
    void start(const EngineOptions &opt);
    /// 请求停止当前任务
    void stop();

    /// 解析用户输入的目标，填充 host / baseUrl / isIp
    static bool normalizeTarget(EngineOptions &opt, QString *error = nullptr);

signals:
    void started();
    void logMessage(const QString &level, const QString &text);
    void stageChanged(const QString &stage, int index, int count);
    void progressChanged(int done, int total);

    void subdomainsFound(const src::DomainAssetList &items);
    void whoisFound(const src::WhoisInfo &info);
    void icpFound(const src::IcpInfo &info);
    void ipLocationFound(const src::IpLocation &info);
    void portsFound(const src::PortResultList &items);
    void fingerprintsFound(const src::WebFingerprintList &items);
    void dirsFound(const src::DirRecordList &items);
    void urlsFound(const src::UrlRecordList &items);
    void cdnFound(const src::CdnRecordList &items);
    void endpointsFound(const src::ApiEndpointList &items);
    void summaryFound(const src::AssetSummaryList &items);

    void finished(bool ok, const QString &summary);

private:
    void runPipeline(EngineOptions opt);
    static bool isModuleEnabled(const QString &id, const EngineOptions &opt);

    std::thread m_runner;
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_cancel{false};
    std::unique_ptr<QThreadPool> m_pool;
    QVector<std::shared_ptr<IReconModule>> m_modules;

    // 累积各模块发现，供流水线末尾的统一排序 / 去重使用
    PortResultList     m_ports;
    WebFingerprintList m_fingerprints;
    DirRecordList      m_dirs;
    ApiEndpointList    m_endpoints;
    CdnRecordList      m_cdn;
};

} // namespace src
