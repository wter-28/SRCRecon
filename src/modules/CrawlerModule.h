#pragma once

#include "modules/IReconModule.h"

namespace src {

/// 爬虫与链接收集：按深度广度抓取页面，提取链接、JS、表单等资产
class CrawlerModule : public IReconModule {
public:
    QString id() const override { return QStringLiteral("crawl"); }
    QString displayName() const override { return QStringLiteral("爬虫与链接收集"); }
    void run(ModuleContext &ctx) override;
};

} // namespace src
