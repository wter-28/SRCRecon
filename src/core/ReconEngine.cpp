#include "core/ReconEngine.h"

#include <QHostAddress>
#include <QStringList>

#include "modules/AssetInfoModule.h"
#include "modules/CrawlerModule.h"
#include "modules/DirScanModule.h"
#include "modules/PortScanModule.h"
#include "modules/SubdomainModule.h"
#include "modules/WebFingerModule.h"

namespace src {

ReconEngine::ReconEngine(QObject *parent)
    : QObject(parent), m_pool(std::make_unique<QThreadPool>())
{
    m_modules << std::make_shared<SubdomainModule>()
              << std::make_shared<AssetInfoModule>()
              << std::make_shared<PortScanModule>()
              << std::make_shared<WebFingerModule>()
              << std::make_shared<DirScanModule>()
              << std::make_shared<CrawlerModule>();
}

ReconEngine::~ReconEngine()
{
    m_cancel.store(true);
    if (m_runner.joinable())
        m_runner.join();
    m_pool->waitForDone();
}

bool ReconEngine::normalizeTarget(EngineOptions &opt, QString *error)
{
    const QString raw = opt.rawTarget.trimmed();
    if (raw.isEmpty()) {
        if (error) *error = QStringLiteral("请输入目标域名、IP 或 URL");
        return false;
    }

    QString scheme;
    QString rest = raw;
    const int schemePos = rest.indexOf(QStringLiteral("://"));
    if (schemePos > 0) {
        scheme = rest.left(schemePos).toLower();
        rest = rest.mid(schemePos + 3);
    }

    QString path;
    const int slashPos = rest.indexOf(QLatin1Char('/'));
    if (slashPos >= 0) {
        path = rest.mid(slashPos);
        rest = rest.left(slashPos);
    }

    QString port;
    if (!rest.contains(QLatin1Char(']'))) {
        const int colonPos = rest.lastIndexOf(QLatin1Char(':'));
        if (colonPos > 0) {
            port = rest.mid(colonPos + 1);
            rest = rest.left(colonPos);
        }
    }

    const QString host = rest.trimmed().toLower();
    if (host.isEmpty()) {
        if (error) *error = QStringLiteral("无法解析目标主机名");
        return false;
    }

    opt.host = host;

    QHostAddress addr;
    opt.isIp = addr.setAddress(host);

    if (scheme != QLatin1String("http") && scheme != QLatin1String("https"))
        scheme = QStringLiteral("http");

    QString base = scheme + QStringLiteral("://") + host;
    if (!port.isEmpty())
        base += QLatin1Char(':') + port;
    base += path;
    opt.baseUrl = base;

    if (opt.isIp && !port.isEmpty()) {
        opt.portSpec = port;  // 用户显式指定端口时，端口扫描范围默认取该端口
    }
    return true;
}

bool ReconEngine::isModuleEnabled(const QString &id, const EngineOptions &opt)
{
    if (id == QLatin1String("subdomain")) return opt.doSubdomain;
    if (id == QLatin1String("asset"))     return opt.doAsset;
    if (id == QLatin1String("port"))      return opt.doPort;
    if (id == QLatin1String("finger"))    return opt.doFinger;
    if (id == QLatin1String("dir"))       return opt.doDir;
    if (id == QLatin1String("crawl"))     return opt.doCrawl;
    return false;
}

void ReconEngine::start(const EngineOptions &opt)
{
    if (m_running.load())
        return;

    if (m_runner.joinable())
        m_runner.join();

    m_cancel.store(false);
    m_running.store(true);

    m_pool->waitForDone();
    m_pool->setMaxThreadCount(qBound(1, opt.threads, 512));

    EngineOptions copy = opt;
    m_runner = std::thread(&ReconEngine::runPipeline, this, copy);
}

void ReconEngine::stop()
{
    m_cancel.store(true);
}

void ReconEngine::runPipeline(EngineOptions opt)
{
    ModuleContext ctx;
    ctx.opt = &opt;
    ctx.pool = m_pool.get();
    ctx.cancelFlag = &m_cancel;

    ctx.log = [this](const QString &level, const QString &text) {
        emit logMessage(level, text);
    };
    ctx.progress = [this](int done, int total) { emit progressChanged(done, total); };
    ctx.addSubdomains = [this](const DomainAssetList &v) {
        if (!v.isEmpty()) emit subdomainsFound(v);
    };
    ctx.addWhois    = [this](const WhoisInfo &v) { emit whoisFound(v); };
    ctx.addIcp      = [this](const IcpInfo &v) { emit icpFound(v); };
    ctx.addIpLocation = [this](const IpLocation &v) { emit ipLocationFound(v); };
    ctx.addPorts    = [this](const PortResultList &v) {
        if (!v.isEmpty()) emit portsFound(v);
    };
    ctx.addFingerprints = [this](const WebFingerprintList &v) {
        if (!v.isEmpty()) emit fingerprintsFound(v);
    };
    ctx.addDirs = [this](const DirRecordList &v) {
        if (!v.isEmpty()) emit dirsFound(v);
    };
    ctx.addUrls = [this](const UrlRecordList &v) {
        if (!v.isEmpty()) emit urlsFound(v);
    };

    emit logMessage(QStringLiteral("info"),
                    QStringLiteral("目标：%1（%2），线程数 %3，超时 %4 ms%5")
                        .arg(opt.host)
                        .arg(opt.isIp ? QStringLiteral("IP") : QStringLiteral("域名"))
                        .arg(opt.threads)
                        .arg(opt.timeoutMs)
                        .arg(opt.demo ? QStringLiteral("，演示模式") : QString()));

    emit started();

    QVector<std::shared_ptr<IReconModule>> queue;
    for (const auto &m : m_modules) {
        if (isModuleEnabled(m->id(), opt))
            queue << m;
    }

    if (queue.isEmpty()) {
        emit logMessage(QStringLiteral("warn"), QStringLiteral("未选择任何收集模块"));
    }

    int index = 0;
    for (const auto &m : queue) {
        if (m_cancel.load())
            break;

        ++index;
        emit stageChanged(m->displayName(), index, queue.size());
        emit progressChanged(0, 1);
        emit logMessage(QStringLiteral("info"),
                        QStringLiteral("=== [%1/%2] %3 ===")
                            .arg(index)
                            .arg(queue.size())
                            .arg(m->displayName()));

        try {
            m->run(ctx);
        } catch (const std::exception &e) {
            emit logMessage(QStringLiteral("error"),
                            QStringLiteral("模块 %1 执行异常：%2")
                                .arg(m->displayName(), QString::fromUtf8(e.what())));
        }
    }

    emit progressChanged(1, 1);

    const bool ok = !m_cancel.load();
    emit finished(ok, ok ? QStringLiteral("信息收集任务完成")
                         : QStringLiteral("信息收集任务已取消"));
    m_running.store(false);
}

} // namespace src
