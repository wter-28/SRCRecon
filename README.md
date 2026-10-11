# SRCRecon · SRC 信息收集工具

基于 **Qt6 + C++17** 的多线程资产信息收集客户端，面向 SRC / 众测 / 授权渗透测试场景。
提供图形界面，一次任务即可完成子域名、Whois/备案、端口、Web 指纹、目录与链接的批量收集，
结果可导出为 CSV / JSON。

> **免责声明**：本工具仅供**已获得合法授权**的安全测试与 SRC 众测使用。
> 请勿对未授权目标发起任何扫描或探测，使用者需自行承担因违规使用产生的一切后果。

---

## 功能特性

| 模块 | 说明 |
| --- | --- |
| **子域名枚举** | 证书透明日志（crt.sh） + 字典 DNS 爆破，自动检测 DNS 泛解析并过滤污染结果 |
| **基础资产信息** | Whois 注册信息解析、ICP 备案查询（可配置接口）、IP 归属地 / ASN |
| **CDN / WAF 识别** | CNAME 链（DoH 解析）与响应头 / Cookie 签名判定 Cloudflare、Akamai、阿里云、腾讯云、网宿等 CDN/WAF；结合**已知 CDN 网段**评估置信度，对非边缘 IP 做 Host 头直连探测**源站候选**，并按 IP 聚合虚拟主机与端口 |
| **端口与服务扫描** | 支持 `common` / `1-1024` / `80,443,8000-8100` 三种端口表达式，按 IP 去重并发 TCP 探测并抓取 Banner 识别服务，命中 CDN 边缘的 IP 自动跳过并标注 |
| **Web 指纹识别** | 提取标题、Server、X-Powered-By，识别 Nginx / Tomcat / Spring Boot / WordPress / ThinkPHP / Shiro 等中间件与 CMS，附 **WAF 标注**与**版本漏洞线索（仅供参考）** |
| **接口 / 暴露面分析** | 探测并解析 **Swagger / OpenAPI** JSON 文档、Actuator 端点、`.git/.env` 等敏感文件，提取真实接口 URL；从表单与 JS 中提取**可测试参数**，输出未授权/配置泄露等风险 |
| **目录/敏感路径探测** | 内置**约 250 条**字典并发探测，识别源码泄露、备份文件、Actuator / Swagger 等敏感接口，含通配响应检测 |
| **爬虫与链接收集** | 广度优先抓取，提取链接、JS、表单等资产，并从页面/JS 中提取 **API 接口路径**与 **API Key / Token / 密钥等敏感信息** |

其他特性：

- **优先级总览**：融合端口、Web 指纹、敏感路径、接口、CDN 源站等发现，按**危险级别与评分降序**排序，快速定位重点资产
- **跨模块智能串联**：子域名、端口、CDN 判定的发现通过共享状态传递给后续模块，Web 目标按存活服务自动扩展，避免每个模块只盯着根目标
- **多线程调度**：独立线程池 + 可配置并发数，UI 全程不卡顿
- **随时取消**：任务执行中可即时停止
- **演示模式**：一键切换为内置离线数据，无网络也能跑通完整流程
- **结果导出**：CSV（带 BOM，Excel 可直接打开）与 JSON，含优先级总览、CDN / 资产、接口 / 暴露面等分页
- **参数持久化**：字典路径、线程数等通过 `QSettings` 记忆

---

## 环境要求

- **Qt** 6.5 及以上（需 `Core` `Gui` `Widgets` `Network` `Concurrent` 模块）
- **CMake** 3.19 及以上
- **C++17** 编译器：MSVC 2019+ / MinGW 11+ / Clang

## 构建

### 命令行（Windows + MinGW 示例）

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_PREFIX_PATH="D:/Qt/6.10.2/mingw_64" `
  -DCMAKE_C_COMPILER="D:/Qt/Tools/mingw1310_64/bin/gcc.exe" `
  -DCMAKE_CXX_COMPILER="D:/Qt/Tools/mingw1310_64/bin/g++.exe" `
  -DCMAKE_MAKE_PROGRAM="D:/Qt/Tools/Ninja/ninja.exe"

cmake --build build --parallel
```

### Qt Creator

直接用 Qt Creator 打开根目录的 `CMakeLists.txt`，选择好 Kit 后构建即可。

### 可选构建选项

| 选项 | 默认 | 说明 |
| --- | --- | --- |
| `SRC_RECON_CONSOLE` | `OFF` | `ON` 时保留控制台窗口，便于调试 |

Windows 下构建完成后会自动调用 `windeployqt` 拷贝 Qt 运行库，产物可直接分发。

## 使用说明

1. 在「目标」输入框中填写域名、IP 或完整 URL（如 `example.com`、`1.2.3.4`、`https://x.com:8443`）。
2. 勾选需要执行的收集模块，按需调整并发线程、超时、字典等参数。
3. 点击「开始收集」；真实模式下会先弹出合法授权确认框。
4. 在右侧各分页查看结果，通过菜单「文件 → 导出为 CSV / JSON」保存。

### 参数说明

- **端口范围**：`common`（内置常见端口）、`1-1024`（区间）、`80,443,8000-8100`（混合列表）。
- **子域名 / 目录字典**：留空使用内置字典；也可选择外部 txt 文件，每行一个条目，`#` 开头为注释。
- **备案接口**：需包含 `{domain}` 占位符，例如 `https://api.vvhan.com/api/icp?url={domain}`。公共接口稳定性有限，正式使用建议替换为自有合规数据源。
- **演示模式**：勾选后完全不发起任何网络请求，使用内置数据演示全部功能。

## 项目结构

```
src/
├── main.cpp                   程序入口、跨线程元类型注册
├── core/
│   ├── Types.h                全部结果数据结构
│   ├── EngineOptions.h        任务参数
│   ├── Wordlists.h            内置字典与端口表
│   ├── NetUtil.{h,cpp}        阻塞式 HTTP / DNS / Whois / TCP 工具集
│   ├── ReconState.h           跨模块共享资产状态（串联合并的基础设施）
│   ├── CdnDetect.{h,cpp}      CDN / WAF 签名库与判定核心（CNAME DoH、响应头）
│   ├── CdnIpRange.{h,cpp}     已知 CDN 网段表（用于置信度评估）
│   ├── JsExtract.{h,cpp}      JS / 页面中的 API 接口与敏感信息提取
│   ├── ExposureDetect.{h,cpp} Swagger/OpenAPI 解析、表单参数、.env 敏感项识别
│   ├── AssetRank.{h,cpp}      资产关联去重与优先级评分
│   ├── VulnDb.{h,cpp}         版本 → CVE 漏洞线索（启发式，仅供参考）
│   ├── ReconEngine.{h,cpp}    多线程调度引擎
│   ├── Settings.{h,cpp}       配置持久化
│   └── DemoData.{h,cpp}       演示数据
├── modules/                   收集模块（统一实现 IReconModule 接口，含 CDN、接口/暴露面模块）
└── ui/                        Qt 界面
```

## 许可证

本项目基于 [MIT License](LICENSE) 开源。
