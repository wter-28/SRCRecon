#pragma once

#include <QString>
#include <QStringList>

namespace src {

/// 一次信息收集任务的全部参数
struct EngineOptions {
    QString rawTarget;             // 用户原始输入
    QString host;                  // 规范化后的主机名 / IP
    QString baseUrl;               // 规范化后的基础 URL（http(s)://host）
    bool    isIp = false;          // 目标是否为 IP

    bool    demo = false;          // 演示模式（离线内置数据）
    int     threads = 32;          // 并发线程数
    int     timeoutMs = 6000;      // 单次请求超时

    // 模块开关
    bool doSubdomain = true;
    bool doAsset     = true;
    bool doPort      = true;
    bool doFinger    = true;
    bool doDir       = true;
    bool doCrawl     = true;

    // 模块参数
    QString subdomainWordlist;                   // 空 = 使用内置字典
    int     subdomainMax = 5000;                 // 最大解析数量
    QString portSpec = QStringLiteral("common"); // common / 1-1024 / 自定义
    QString dirWordlist;                         // 空 = 使用内置字典
    bool    crawlExternal = false;               // 是否跟随站外链接
    int     crawlMaxPages = 80;
    int     crawlDepth = 2;

    QString icpApiUrl;  // 可选的 ICP 备案查询接口模板，含 {domain}
};

} // namespace src
