#include "core/Settings.h"

#include <QSettings>

#include "core/EngineOptions.h"

namespace src {
namespace settings {

namespace {
const char *kOrg = "SRCRecon";
const char *kApp = "SRCRecon";

QString key(const char *k) { return QString::fromLatin1(k); }
} // namespace

QString icpApiUrl()
{
    QSettings s(QString::fromLatin1(kOrg), QString::fromLatin1(kApp));
    return s.value(key("icp/apiUrl"),
                   QStringLiteral("https://api.vvhan.com/api/icp?url={domain}"))
        .toString();
}

void setIcpApiUrl(const QString &url)
{
    QSettings s(QString::fromLatin1(kOrg), QString::fromLatin1(kApp));
    s.setValue(key("icp/apiUrl"), url);
}

void load(EngineOptions &opt)
{
    QSettings s(QString::fromLatin1(kOrg), QString::fromLatin1(kApp));

    opt.threads    = s.value(key("engine/threads"), opt.threads).toInt();
    opt.timeoutMs  = s.value(key("engine/timeout"), opt.timeoutMs).toInt();
    opt.demo       = s.value(key("engine/demo"), opt.demo).toBool();

    opt.doSubdomain = s.value(key("module/subdomain"), opt.doSubdomain).toBool();
    opt.doCdn       = s.value(key("module/cdn"), opt.doCdn).toBool();
    opt.doAsset     = s.value(key("module/asset"), opt.doAsset).toBool();
    opt.doPort      = s.value(key("module/port"), opt.doPort).toBool();
    opt.doFinger    = s.value(key("module/finger"), opt.doFinger).toBool();
    opt.doDir       = s.value(key("module/dir"), opt.doDir).toBool();
    opt.doCrawl     = s.value(key("module/crawl"), opt.doCrawl).toBool();
    opt.doExposure  = s.value(key("module/exposure"), opt.doExposure).toBool();

    opt.subdomainWordlist = s.value(key("wordlist/subdomain")).toString();
    opt.dirWordlist       = s.value(key("wordlist/dir")).toString();
    opt.portSpec          = s.value(key("port/spec"), opt.portSpec).toString();
    opt.crawlExternal     = s.value(key("crawl/external"), opt.crawlExternal).toBool();
    opt.crawlMaxPages     = s.value(key("crawl/maxPages"), opt.crawlMaxPages).toInt();
    opt.crawlDepth        = s.value(key("crawl/depth"), opt.crawlDepth).toInt();
    opt.subdomainMax      = s.value(key("subdomain/max"), opt.subdomainMax).toInt();
    opt.exposureMaxProbe  = s.value(key("exposure/maxProbe"), opt.exposureMaxProbe).toInt();

    opt.icpApiUrl = icpApiUrl();
}

void save(const EngineOptions &opt)
{
    QSettings s(QString::fromLatin1(kOrg), QString::fromLatin1(kApp));

    s.setValue(key("engine/threads"), opt.threads);
    s.setValue(key("engine/timeout"), opt.timeoutMs);
    s.setValue(key("engine/demo"), opt.demo);

    s.setValue(key("module/subdomain"), opt.doSubdomain);
    s.setValue(key("module/cdn"), opt.doCdn);
    s.setValue(key("module/asset"), opt.doAsset);
    s.setValue(key("module/port"), opt.doPort);
    s.setValue(key("module/finger"), opt.doFinger);
    s.setValue(key("module/dir"), opt.doDir);
    s.setValue(key("module/crawl"), opt.doCrawl);
    s.setValue(key("module/exposure"), opt.doExposure);

    s.setValue(key("wordlist/subdomain"), opt.subdomainWordlist);
    s.setValue(key("wordlist/dir"), opt.dirWordlist);
    s.setValue(key("port/spec"), opt.portSpec);
    s.setValue(key("crawl/external"), opt.crawlExternal);
    s.setValue(key("crawl/maxPages"), opt.crawlMaxPages);
    s.setValue(key("crawl/depth"), opt.crawlDepth);
    s.setValue(key("subdomain/max"), opt.subdomainMax);
}

} // namespace settings
} // namespace src
