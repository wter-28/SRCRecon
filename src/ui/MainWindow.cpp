#include "ui/MainWindow.h"

#include <QApplication>
#include <QCheckBox>
#include <QCloseEvent>
#include <QDateTime>
#include <QFile>
#include <QFileDialog>
#include <QFormLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QMenuBar>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QScrollArea>
#include <QSpinBox>
#include <QSplitter>
#include <QStatusBar>
#include <QStringConverter>
#include <QTabWidget>
#include <QTableWidget>
#include <QTextStream>
#include <QTime>
#include <QVBoxLayout>

#include "core/ReconEngine.h"
#include "core/Settings.h"

namespace src {

namespace {

constexpr int kMaxTableRows = 20000;

QTableWidget *makeTable(QWidget *parent, const QStringList &headers)
{
    auto *t = new QTableWidget(parent);
    t->setColumnCount(headers.size());
    t->setHorizontalHeaderLabels(headers);
    t->setEditTriggers(QAbstractItemView::NoEditTriggers);
    t->setSelectionBehavior(QAbstractItemView::SelectRows);
    t->setSelectionMode(QAbstractItemView::ExtendedSelection);
    t->setAlternatingRowColors(true);
    t->setSortingEnabled(false);
    t->verticalHeader()->setVisible(false);
    t->verticalHeader()->setDefaultSectionSize(22);
    t->horizontalHeader()->setStretchLastSection(true);
    t->horizontalHeader()->setHighlightSections(false);
    return t;
}

void addRow(QTableWidget *t, const QStringList &cols)
{
    if (t->rowCount() >= kMaxTableRows)
        return;

    const int r = t->rowCount();
    t->insertRow(r);
    for (int c = 0; c < cols.size() && c < t->columnCount(); ++c) {
        auto *item = new QTableWidgetItem(cols.at(c));
        item->setToolTip(cols.at(c));
        t->setItem(r, c, item);
    }
}

QString csvEscape(const QString &s)
{
    QString v = s;
    v.replace(QLatin1Char('"'), QStringLiteral("\"\""));
    if (v.contains(QLatin1Char(',')) || v.contains(QLatin1Char('"'))
        || v.contains(QLatin1Char('\n')))
        return QLatin1Char('"') + v + QLatin1Char('"');
    return v;
}

QString fmtSize(qint64 n)
{
    return n > 0 ? QString::number(n) : QStringLiteral("-");
}

} // namespace

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), m_engine(new ReconEngine(this))
{
    setWindowTitle(QStringLiteral("SRC 信息收集工具  v1.0"));
    resize(1360, 820);

    buildMenu();
    buildUi();

    connect(m_engine, &ReconEngine::started, this, &MainWindow::onEngineStarted);
    connect(m_engine, &ReconEngine::logMessage, this, &MainWindow::onLog);
    connect(m_engine, &ReconEngine::stageChanged, this, &MainWindow::onStage);
    connect(m_engine, &ReconEngine::progressChanged, this, &MainWindow::onProgress);
    connect(m_engine, &ReconEngine::subdomainsFound, this, &MainWindow::onSubdomains);
    connect(m_engine, &ReconEngine::whoisFound, this, &MainWindow::onWhois);
    connect(m_engine, &ReconEngine::icpFound, this, &MainWindow::onIcp);
    connect(m_engine, &ReconEngine::ipLocationFound, this, &MainWindow::onIpLocation);
    connect(m_engine, &ReconEngine::portsFound, this, &MainWindow::onPorts);
    connect(m_engine, &ReconEngine::fingerprintsFound, this, &MainWindow::onFingerprints);
    connect(m_engine, &ReconEngine::dirsFound, this, &MainWindow::onDirs);
    connect(m_engine, &ReconEngine::urlsFound, this, &MainWindow::onUrls);
    connect(m_engine, &ReconEngine::cdnFound, this, &MainWindow::onCdn);
    connect(m_engine, &ReconEngine::finished, this, &MainWindow::onEngineFinished);

    connect(m_startBtn, &QPushButton::clicked, this, &MainWindow::onStart);
    connect(m_stopBtn, &QPushButton::clicked, this, &MainWindow::onStop);
    connect(m_targetEdit, &QLineEdit::returnPressed, this, &MainWindow::onStart);

    EngineOptions opt;
    settings::load(opt);
    applyOptions(opt);

    setBusy(false);
    updateTabTitles();

    appendLog(QStringLiteral("info"),
              QStringLiteral("请仅对已获得合法授权的目标进行信息收集。"));
}

MainWindow::~MainWindow()
{
    if (m_engine)
        m_engine->stop();
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    if (m_engine && m_engine->isRunning()) {
        const auto ret = QMessageBox::question(this, QStringLiteral("确认退出"),
                                              QStringLiteral("任务仍在执行，确定要退出吗？"));
        if (ret != QMessageBox::Yes) {
            event->ignore();
            return;
        }
        m_engine->stop();
    }
    event->accept();
}

void MainWindow::buildMenu()
{
    QMenu *fileMenu = menuBar()->addMenu(QStringLiteral("文件(&F)"));
    fileMenu->addAction(QStringLiteral("导出为 CSV..."), this, &MainWindow::onExportCsv);
    fileMenu->addAction(QStringLiteral("导出为 JSON..."), this, &MainWindow::onExportJson);
    fileMenu->addSeparator();
    fileMenu->addAction(QStringLiteral("退出"), this, &QWidget::close);

    QMenu *helpMenu = menuBar()->addMenu(QStringLiteral("帮助(&H)"));
    helpMenu->addAction(QStringLiteral("关于"), this, &MainWindow::onAbout);
}

void MainWindow::buildUi()
{
    auto *splitter = new QSplitter(Qt::Horizontal, this);
    splitter->addWidget(buildSidePanel());
    splitter->addWidget(buildResultTabs());
    splitter->setStretchFactor(0, 0);
    splitter->setStretchFactor(1, 1);
    splitter->setSizes({360, 1000});
    setCentralWidget(splitter);

    m_stageLabel = new QLabel(QStringLiteral("就绪"));
    m_progress = new QProgressBar;
    m_progress->setFixedWidth(240);
    m_progress->setRange(0, 100);
    m_progress->setValue(0);

    statusBar()->addWidget(m_stageLabel, 1);
    statusBar()->addPermanentWidget(m_progress);
}

QWidget *MainWindow::buildSidePanel()
{
    auto *panel = new QWidget;
    auto *v = new QVBoxLayout(panel);
    v->setContentsMargins(10, 10, 10, 10);
    v->setSpacing(10);

    // ---- 目标 ----
    auto *targetBox = new QGroupBox(QStringLiteral("目标"));
    auto *tv = new QVBoxLayout(targetBox);
    m_targetEdit = new QLineEdit;
    m_targetEdit->setPlaceholderText(QStringLiteral("example.com / 1.2.3.4 / https://x.com:8443"));
    tv->addWidget(m_targetEdit);
    auto *tip = new QLabel(QStringLiteral("支持域名、IP 或完整 URL"));
    tip->setStyleSheet(QStringLiteral("color:#888;font-size:11px;"));
    tv->addWidget(tip);
    v->addWidget(targetBox);

    // ---- 模块 ----
    auto *modBox = new QGroupBox(QStringLiteral("收集模块"));
    auto *mv = new QVBoxLayout(modBox);
    m_cbSub = new QCheckBox(QStringLiteral("子域名枚举（CT 日志 + 字典）"));
    m_cbCdn = new QCheckBox(QStringLiteral("CDN / WAF 识别与资产聚合"));
    m_cbAsset = new QCheckBox(QStringLiteral("基础资产信息（Whois / 备案 / IP）"));
    m_cbPort = new QCheckBox(QStringLiteral("端口与服务扫描（按 IP 聚合）"));
    m_cbFinger = new QCheckBox(QStringLiteral("Web 指纹识别（WAF / CVE 线索）"));
    m_cbDir = new QCheckBox(QStringLiteral("目录 / 敏感路径探测"));
    m_cbCrawl = new QCheckBox(QStringLiteral("爬虫 / JS 接口与敏感信息收集"));
    for (QCheckBox *cb : {m_cbSub, m_cbCdn, m_cbAsset, m_cbPort, m_cbFinger, m_cbDir, m_cbCrawl})
        mv->addWidget(cb);
    v->addWidget(modBox);

    // ---- 参数 ----
    auto *paramBox = new QGroupBox(QStringLiteral("参数配置"));
    auto *form = new QFormLayout(paramBox);
    form->setLabelAlignment(Qt::AlignRight);

    m_threadsSpin = new QSpinBox;
    m_threadsSpin->setRange(1, 512);
    form->addRow(QStringLiteral("并发线程"), m_threadsSpin);

    m_timeoutSpin = new QSpinBox;
    m_timeoutSpin->setRange(500, 60000);
    m_timeoutSpin->setSingleStep(500);
    m_timeoutSpin->setSuffix(QStringLiteral(" ms"));
    form->addRow(QStringLiteral("请求超时"), m_timeoutSpin);

    m_portSpecEdit = new QLineEdit;
    m_portSpecEdit->setPlaceholderText(QStringLiteral("common / 1-1024 / 80,443,8000-8100"));
    form->addRow(QStringLiteral("端口范围"), m_portSpecEdit);

    auto *subRow = new QWidget;
    auto *subLay = new QHBoxLayout(subRow);
    subLay->setContentsMargins(0, 0, 0, 0);
    m_subDictEdit = new QLineEdit;
    m_subDictEdit->setPlaceholderText(QStringLiteral("留空使用内置字典"));
    auto *subBtn = new QPushButton(QStringLiteral("..."));
    subBtn->setFixedWidth(30);
    subLay->addWidget(m_subDictEdit);
    subLay->addWidget(subBtn);
    form->addRow(QStringLiteral("子域名字典"), subRow);
    connect(subBtn, &QPushButton::clicked, this, &MainWindow::onBrowseSubdomainDict);

    auto *dirRow = new QWidget;
    auto *dirLay = new QHBoxLayout(dirRow);
    dirLay->setContentsMargins(0, 0, 0, 0);
    m_dirDictEdit = new QLineEdit;
    m_dirDictEdit->setPlaceholderText(QStringLiteral("留空使用内置字典"));
    auto *dirBtn = new QPushButton(QStringLiteral("..."));
    dirBtn->setFixedWidth(30);
    dirLay->addWidget(m_dirDictEdit);
    dirLay->addWidget(dirBtn);
    form->addRow(QStringLiteral("目录字典"), dirRow);
    connect(dirBtn, &QPushButton::clicked, this, &MainWindow::onBrowseDirDict);

    m_crawlPagesSpin = new QSpinBox;
    m_crawlPagesSpin->setRange(1, 5000);
    form->addRow(QStringLiteral("爬虫页数上限"), m_crawlPagesSpin);

    m_crawlDepthSpin = new QSpinBox;
    m_crawlDepthSpin->setRange(0, 6);
    form->addRow(QStringLiteral("爬虫深度"), m_crawlDepthSpin);

    m_crawlExternalCheck = new QCheckBox(QStringLiteral("跟随站外链接"));
    form->addRow(QString(), m_crawlExternalCheck);

    m_icpApiEdit = new QLineEdit;
    m_icpApiEdit->setPlaceholderText(QStringLiteral("含 {domain} 的接口地址"));
    form->addRow(QStringLiteral("备案接口"), m_icpApiEdit);

    v->addWidget(paramBox);

    m_demoCheck = new QCheckBox(QStringLiteral("演示模式（不发起真实请求）"));
    v->addWidget(m_demoCheck);

    auto *btnRow = new QHBoxLayout;
    m_startBtn = new QPushButton(QStringLiteral("开始收集"));
    m_startBtn->setMinimumHeight(34);
    m_stopBtn = new QPushButton(QStringLiteral("停止"));
    m_stopBtn->setMinimumHeight(34);
    btnRow->addWidget(m_startBtn, 2);
    btnRow->addWidget(m_stopBtn, 1);
    v->addLayout(btnRow);
    v->addStretch();

    auto *scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setWidget(panel);
    scroll->setMinimumWidth(340);
    return scroll;
}

QWidget *MainWindow::buildResultTabs()
{
    m_tabs = new QTabWidget(this);

    m_subTable    = makeTable(this, {QStringLiteral("主机"), QStringLiteral("IP"), QStringLiteral("来源")});
    m_assetTable  = makeTable(this, {QStringLiteral("类别"), QStringLiteral("项目"), QStringLiteral("值")});
    m_cdnTable    = makeTable(this, {QStringLiteral("主机"), QStringLiteral("IP"),
                                     QStringLiteral("类别"), QStringLiteral("厂商"),
                                     QStringLiteral("CNAME"), QStringLiteral("源站候选"),
                                     QStringLiteral("依据")});
    m_portTable   = makeTable(this, {QStringLiteral("主机"), QStringLiteral("端口"),
                                     QStringLiteral("服务"), QStringLiteral("Banner")});
    m_fingerTable = makeTable(this, {QStringLiteral("URL"), QStringLiteral("状态"), QStringLiteral("标题"),
                                     QStringLiteral("Server"), QStringLiteral("X-Powered-By"),
                                     QStringLiteral("指纹"), QStringLiteral("WAF"),
                                     QStringLiteral("漏洞线索")});
    m_dirTable    = makeTable(this, {QStringLiteral("URL"), QStringLiteral("状态"),
                                     QStringLiteral("长度"), QStringLiteral("类型"),
                                     QStringLiteral("备注")});
    m_urlTable    = makeTable(this, {QStringLiteral("URL"), QStringLiteral("状态"),
                                     QStringLiteral("类型"), QStringLiteral("长度"),
                                     QStringLiteral("来源")});

    m_logView = new QPlainTextEdit(this);
    m_logView->setReadOnly(true);
    m_logView->setMaximumBlockCount(5000);
    m_logView->setStyleSheet(QStringLiteral("font-family:Consolas,'Microsoft YaHei';font-size:12px;"));

    m_tabs->addTab(m_subTable, QStringLiteral("子域名"));
    m_tabs->addTab(m_assetTable, QStringLiteral("资产信息"));
    m_tabs->addTab(m_cdnTable, QStringLiteral("CDN/资产"));
    m_tabs->addTab(m_portTable, QStringLiteral("端口"));
    m_tabs->addTab(m_fingerTable, QStringLiteral("Web 指纹"));
    m_tabs->addTab(m_dirTable, QStringLiteral("目录探测"));
    m_tabs->addTab(m_urlTable, QStringLiteral("URL"));
    m_tabs->addTab(m_logView, QStringLiteral("运行日志"));
    return m_tabs;
}

void MainWindow::applyOptions(const EngineOptions &opt)
{
    m_targetEdit->setText(opt.rawTarget);
    m_cbSub->setChecked(opt.doSubdomain);
    m_cbCdn->setChecked(opt.doCdn);
    m_cbAsset->setChecked(opt.doAsset);
    m_cbPort->setChecked(opt.doPort);
    m_cbFinger->setChecked(opt.doFinger);
    m_cbDir->setChecked(opt.doDir);
    m_cbCrawl->setChecked(opt.doCrawl);
    m_threadsSpin->setValue(opt.threads);
    m_timeoutSpin->setValue(opt.timeoutMs);
    m_portSpecEdit->setText(opt.portSpec);
    m_subDictEdit->setText(opt.subdomainWordlist);
    m_dirDictEdit->setText(opt.dirWordlist);
    m_crawlPagesSpin->setValue(opt.crawlMaxPages);
    m_crawlDepthSpin->setValue(opt.crawlDepth);
    m_crawlExternalCheck->setChecked(opt.crawlExternal);
    m_demoCheck->setChecked(opt.demo);
    m_icpApiEdit->setText(opt.icpApiUrl);
}

void MainWindow::collectOptions(EngineOptions &opt) const
{
    opt.rawTarget = m_targetEdit->text().trimmed();
    opt.doSubdomain = m_cbSub->isChecked();
    opt.doCdn = m_cbCdn->isChecked();
    opt.doAsset = m_cbAsset->isChecked();
    opt.doPort = m_cbPort->isChecked();
    opt.doFinger = m_cbFinger->isChecked();
    opt.doDir = m_cbDir->isChecked();
    opt.doCrawl = m_cbCrawl->isChecked();
    opt.threads = m_threadsSpin->value();
    opt.timeoutMs = m_timeoutSpin->value();
    opt.portSpec = m_portSpecEdit->text().trimmed();
    opt.subdomainWordlist = m_subDictEdit->text().trimmed();
    opt.dirWordlist = m_dirDictEdit->text().trimmed();
    opt.crawlMaxPages = m_crawlPagesSpin->value();
    opt.crawlDepth = m_crawlDepthSpin->value();
    opt.crawlExternal = m_crawlExternalCheck->isChecked();
    opt.demo = m_demoCheck->isChecked();
    opt.icpApiUrl = m_icpApiEdit->text().trimmed();
}

void MainWindow::onStart()
{
    EngineOptions opt;
    collectOptions(opt);

    QString error;
    if (!ReconEngine::normalizeTarget(opt, &error)) {
        QMessageBox::warning(this, QStringLiteral("参数错误"), error);
        return;
    }

    if (!m_demoCheck->isChecked()) {
        const auto ret = QMessageBox::question(
            this, QStringLiteral("合法授权确认"),
            QStringLiteral("请确认你已获得对目标 \"%1\" 进行安全测试的合法授权。\n是否继续？")
                .arg(opt.host));
        if (ret != QMessageBox::Yes)
            return;
    }

    settings::save(opt);
    settings::setIcpApiUrl(opt.icpApiUrl);

    clearResults();
    m_tabs->setCurrentIndex(7);
    appendLog(QStringLiteral("info"), QStringLiteral("任务启动：%1").arg(opt.rawTarget));
    m_engine->start(opt);
}

void MainWindow::onStop()
{
    if (!m_engine->isRunning())
        return;
    appendLog(QStringLiteral("warn"), QStringLiteral("已发送停止请求，等待当前请求返回..."));
    m_engine->stop();
    m_stageLabel->setText(QStringLiteral("正在停止..."));
}

void MainWindow::onBrowseSubdomainDict()
{
    const QString f = QFileDialog::getOpenFileName(this, QStringLiteral("选择子域名字典"));
    if (!f.isEmpty())
        m_subDictEdit->setText(f);
}

void MainWindow::onBrowseDirDict()
{
    const QString f = QFileDialog::getOpenFileName(this, QStringLiteral("选择目录字典"));
    if (!f.isEmpty())
        m_dirDictEdit->setText(f);
}

void MainWindow::setBusy(bool busy)
{
    m_startBtn->setEnabled(!busy);
    m_stopBtn->setEnabled(busy);
    m_targetEdit->setEnabled(!busy);
}

void MainWindow::clearResults()
{
    m_subdomains.clear();
    m_ports.clear();
    m_fingerprints.clear();
    m_dirs.clear();
    m_urls.clear();
    m_whoisList.clear();
    m_icpList.clear();
    m_ipList.clear();
    m_cdnRecords.clear();

    for (QTableWidget *t : {m_subTable, m_assetTable, m_cdnTable, m_portTable, m_fingerTable,
                            m_dirTable, m_urlTable})
        t->setRowCount(0);

    m_logView->clear();
    m_progress->setValue(0);
    updateTabTitles();
}

void MainWindow::updateTabTitles()
{
    m_tabs->setTabText(0, QStringLiteral("子域名 (%1)").arg(m_subdomains.size()));
    m_tabs->setTabText(1, QStringLiteral("资产信息 (%1)")
                              .arg(m_whoisList.size() + m_icpList.size() + m_ipList.size()));
    m_tabs->setTabText(2, QStringLiteral("CDN/资产 (%1)").arg(m_cdnRecords.size()));
    m_tabs->setTabText(3, QStringLiteral("端口 (%1)").arg(m_ports.size()));
    m_tabs->setTabText(4, QStringLiteral("Web 指纹 (%1)").arg(m_fingerprints.size()));
    m_tabs->setTabText(5, QStringLiteral("目录探测 (%1)").arg(m_dirs.size()));
    m_tabs->setTabText(6, QStringLiteral("URL (%1)").arg(m_urls.size()));
}

void MainWindow::appendLog(const QString &level, const QString &text)
{
    QString color = QStringLiteral("#333333");
    if (level == QLatin1String("ok"))         color = QStringLiteral("#1a7f37");
    else if (level == QLatin1String("warn"))  color = QStringLiteral("#b26a00");
    else if (level == QLatin1String("error")) color = QStringLiteral("#c0392b");

    const QString ts = QTime::currentTime().toString(QStringLiteral("HH:mm:ss"));
    m_logView->appendHtml(QStringLiteral("<span style=\"color:#999;\">[%1]</span> "
                                         "<span style=\"color:%2;\">%3</span>")
                              .arg(ts, color, text.toHtmlEscaped()));
}

// ---------------- 引擎信号 ----------------

void MainWindow::onEngineStarted()
{
    setBusy(true);
    m_stageLabel->setText(QStringLiteral("任务执行中..."));
}

void MainWindow::onEngineFinished(bool ok, const QString &summary)
{
    setBusy(false);
    m_stageLabel->setText(summary);
    m_progress->setRange(0, 100);
    m_progress->setValue(ok ? 100 : 0);
    appendLog(ok ? QStringLiteral("ok") : QStringLiteral("warn"), summary);
    updateTabTitles();
}

void MainWindow::onLog(const QString &level, const QString &text)
{
    appendLog(level, text);
}

void MainWindow::onStage(const QString &stage, int index, int count)
{
    m_stageLabel->setText(QStringLiteral("阶段 %1/%2：%3").arg(index).arg(count).arg(stage));
}

void MainWindow::onProgress(int done, int total)
{
    if (total <= 0) {
        m_progress->setRange(0, 0);
        return;
    }
    m_progress->setRange(0, total);
    m_progress->setValue(qBound(0, done, total));
}

void MainWindow::onSubdomains(const DomainAssetList &items)
{
    m_subdomains += items;
    m_subTable->setUpdatesEnabled(false);
    for (const DomainAsset &d : items)
        addRow(m_subTable, {d.host, d.ip.isEmpty() ? QStringLiteral("-") : d.ip, d.source});
    m_subTable->setUpdatesEnabled(true);
    m_subTable->resizeColumnToContents(0);
    updateTabTitles();
}

void MainWindow::onWhois(const WhoisInfo &info)
{
    m_whoisList << info;
    refreshAssetTable();
}

void MainWindow::onIcp(const IcpInfo &info)
{
    m_icpList << info;
    refreshAssetTable();
}

void MainWindow::onIpLocation(const IpLocation &info)
{
    m_ipList << info;
    refreshAssetTable();
}

void MainWindow::refreshAssetTable()
{
    m_assetTable->setUpdatesEnabled(false);
    m_assetTable->setRowCount(0);

    for (const WhoisInfo &w : m_whoisList) {
        const QString cat = QStringLiteral("Whois");
        addRow(m_assetTable, {cat, QStringLiteral("域名"), w.domain});
        addRow(m_assetTable, {cat, QStringLiteral("注册商"), w.registrar});
        addRow(m_assetTable, {cat, QStringLiteral("注册人/单位"), w.registrant});
        addRow(m_assetTable, {cat, QStringLiteral("注册时间"), w.creationDate});
        addRow(m_assetTable, {cat, QStringLiteral("到期时间"), w.expiryDate});
        addRow(m_assetTable, {cat, QStringLiteral("更新时间"), w.updatedDate});
        addRow(m_assetTable, {cat, QStringLiteral("DNS 服务器"), w.nameServers});
        addRow(m_assetTable, {cat, QStringLiteral("域名状态"), w.status});
    }
    for (const IcpInfo &i : m_icpList) {
        const QString cat = QStringLiteral("备案");
        addRow(m_assetTable, {cat, QStringLiteral("域名"), i.domain});
        addRow(m_assetTable, {cat, QStringLiteral("备案号"), i.number});
        addRow(m_assetTable, {cat, QStringLiteral("主办单位"), i.company});
        addRow(m_assetTable, {cat, QStringLiteral("单位性质"), i.nature});
        addRow(m_assetTable, {cat, QStringLiteral("网站名称"), i.siteName});
        addRow(m_assetTable, {cat, QStringLiteral("审核时间"), i.auditDate});
    }
    for (const IpLocation &l : m_ipList) {
        const QString cat = QStringLiteral("IP归属");
        addRow(m_assetTable, {cat, QStringLiteral("IP"), l.ip});
        addRow(m_assetTable, {cat, QStringLiteral("国家/地区"), l.country});
        addRow(m_assetTable, {cat, QStringLiteral("省份"), l.region});
        addRow(m_assetTable, {cat, QStringLiteral("城市"), l.city});
        addRow(m_assetTable, {cat, QStringLiteral("运营商"), l.isp});
        addRow(m_assetTable, {cat, QStringLiteral("组织"), l.org});
        addRow(m_assetTable, {cat, QStringLiteral("ASN"), l.asn});
        addRow(m_assetTable, {cat, QStringLiteral("时区"), l.timezone});
    }

    m_assetTable->setUpdatesEnabled(true);
    m_assetTable->resizeColumnToContents(0);
    updateTabTitles();
}

void MainWindow::onPorts(const PortResultList &items)
{
    m_ports += items;
    m_portTable->setUpdatesEnabled(false);
    for (const PortResult &p : items)
        addRow(m_portTable, {p.host, QString::number(p.port), p.service, p.banner});
    m_portTable->setUpdatesEnabled(true);
    m_portTable->resizeColumnToContents(1);
    updateTabTitles();
}

void MainWindow::onFingerprints(const WebFingerprintList &items)
{
    m_fingerprints += items;
    m_fingerTable->setUpdatesEnabled(false);
    for (const WebFingerprint &f : items)
        addRow(m_fingerTable, {f.url, QString::number(f.statusCode), f.title, f.server, f.poweredBy,
                               f.technologies, f.waf, f.vulnHint});
    m_fingerTable->setUpdatesEnabled(true);
    updateTabTitles();
}

void MainWindow::onDirs(const DirRecordList &items)
{
    m_dirs += items;
    m_dirTable->setUpdatesEnabled(false);
    for (const DirRecord &d : items)
        addRow(m_dirTable, {d.url, QString::number(d.statusCode), fmtSize(d.length),
                            d.contentType, d.note});
    m_dirTable->setUpdatesEnabled(true);
    updateTabTitles();
}

void MainWindow::onUrls(const UrlRecordList &items)
{
    m_urls += items;
    m_urlTable->setUpdatesEnabled(false);
    for (const UrlRecord &u : items)
        addRow(m_urlTable, {u.url, u.statusCode > 0 ? QString::number(u.statusCode)
                                                    : QStringLiteral("-"),
                            u.contentType, fmtSize(u.length), u.source});
    m_urlTable->setUpdatesEnabled(true);
    updateTabTitles();
}

void MainWindow::onCdn(const CdnRecordList &items)
{
    m_cdnRecords += items;
    m_cdnTable->setUpdatesEnabled(false);
    for (const CdnRecord &c : items)
        addRow(m_cdnTable, {c.host, c.ip, c.category,
                            c.vendor.isEmpty() ? QStringLiteral("-") : c.vendor,
                            c.cname.isEmpty() ? QStringLiteral("-") : c.cname,
                            c.realIp.isEmpty() ? QStringLiteral("-") : c.realIp,
                            c.reason});
    m_cdnTable->setUpdatesEnabled(true);
    updateTabTitles();
}

// ---------------- 导出 ----------------

void MainWindow::onExportCsv()
{
    const QString file = QFileDialog::getSaveFileName(
        this, QStringLiteral("导出 CSV"), QStringLiteral("src-recon-result.csv"),
        QStringLiteral("CSV 文件 (*.csv)"));
    if (file.isEmpty())
        return;

    QFile f(file);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, QStringLiteral("导出失败"), f.errorString());
        return;
    }

    QTextStream out(&f);
    out.setEncoding(QStringConverter::Utf8);
    out << QChar(0xFEFF);  // BOM，便于 Excel 正确识别 UTF-8

    auto section = [&out](const QString &title) {
        out << "\n# " << title << "\n";
    };

    section(QStringLiteral("子域名"));
    out << "主机,IP,来源\n";
    for (const DomainAsset &d : m_subdomains)
        out << csvEscape(d.host) << ',' << csvEscape(d.ip) << ',' << csvEscape(d.source) << '\n';

    section(QStringLiteral("资产信息"));
    out << "类别,项目,值\n";
    for (int r = 0; r < m_assetTable->rowCount(); ++r) {
        QStringList cols;
        for (int c = 0; c < 3; ++c)
            cols << (m_assetTable->item(r, c) ? m_assetTable->item(r, c)->text() : QString());
        out << csvEscape(cols.at(0)) << ',' << csvEscape(cols.at(1)) << ',' << csvEscape(cols.at(2))
            << '\n';
    }

    section(QStringLiteral("开放端口"));
    out << "主机,端口,服务,Banner\n";
    for (const PortResult &p : m_ports)
        out << csvEscape(p.host) << ',' << p.port << ',' << csvEscape(p.service) << ','
            << csvEscape(p.banner) << '\n';

    section(QStringLiteral("CDN / 资产"));
    out << "主机,IP,类别,厂商,CNAME,源站候选,依据\n";
    for (const CdnRecord &c : m_cdnRecords)
        out << csvEscape(c.host) << ',' << csvEscape(c.ip) << ',' << csvEscape(c.category) << ','
            << csvEscape(c.vendor) << ',' << csvEscape(c.cname) << ',' << csvEscape(c.realIp) << ','
            << csvEscape(c.reason) << '\n';

    section(QStringLiteral("Web 指纹"));
    out << "URL,状态,标题,Server,X-Powered-By,指纹,WAF,漏洞线索\n";
    for (const WebFingerprint &w : m_fingerprints)
        out << csvEscape(w.url) << ',' << w.statusCode << ',' << csvEscape(w.title) << ','
            << csvEscape(w.server) << ',' << csvEscape(w.poweredBy) << ','
            << csvEscape(w.technologies) << ',' << csvEscape(w.waf) << ','
            << csvEscape(w.vulnHint) << '\n';

    section(QStringLiteral("目录探测"));
    out << "URL,状态,长度,类型,备注\n";
    for (const DirRecord &d : m_dirs)
        out << csvEscape(d.url) << ',' << d.statusCode << ',' << d.length << ','
            << csvEscape(d.contentType) << ',' << csvEscape(d.note) << '\n';

    section(QStringLiteral("URL"));
    out << "URL,状态,类型,长度,来源\n";
    for (const UrlRecord &u : m_urls)
        out << csvEscape(u.url) << ',' << u.statusCode << ',' << csvEscape(u.contentType) << ','
            << u.length << ',' << csvEscape(u.source) << '\n';

    f.close();
    QMessageBox::information(this, QStringLiteral("导出完成"), QStringLiteral("已导出：%1").arg(file));
}

void MainWindow::onExportJson()
{
    const QString file = QFileDialog::getSaveFileName(
        this, QStringLiteral("导出 JSON"), QStringLiteral("src-recon-result.json"),
        QStringLiteral("JSON 文件 (*.json)"));
    if (file.isEmpty())
        return;

    QJsonObject root;
    root.insert(QStringLiteral("tool"), QStringLiteral("SRCRecon"));

    QJsonArray subs;
    for (const DomainAsset &d : m_subdomains)
        subs.append(QJsonObject{{QStringLiteral("host"), d.host},
                                {QStringLiteral("ip"), d.ip},
                                {QStringLiteral("source"), d.source}});
    root.insert(QStringLiteral("subdomains"), subs);

    QJsonArray whoisArr;
    for (const WhoisInfo &w : m_whoisList)
        whoisArr.append(QJsonObject{
            {QStringLiteral("domain"), w.domain}, {QStringLiteral("registrar"), w.registrar},
            {QStringLiteral("registrant"), w.registrant},
            {QStringLiteral("creationDate"), w.creationDate},
            {QStringLiteral("expiryDate"), w.expiryDate},
            {QStringLiteral("nameServers"), w.nameServers}, {QStringLiteral("status"), w.status}});
    root.insert(QStringLiteral("whois"), whoisArr);

    QJsonArray icpArr;
    for (const IcpInfo &i : m_icpList)
        icpArr.append(QJsonObject{{QStringLiteral("domain"), i.domain},
                                  {QStringLiteral("number"), i.number},
                                  {QStringLiteral("company"), i.company},
                                  {QStringLiteral("nature"), i.nature},
                                  {QStringLiteral("siteName"), i.siteName},
                                  {QStringLiteral("auditDate"), i.auditDate}});
    root.insert(QStringLiteral("icp"), icpArr);

    QJsonArray ipArr;
    for (const IpLocation &l : m_ipList)
        ipArr.append(QJsonObject{{QStringLiteral("ip"), l.ip},
                                 {QStringLiteral("country"), l.country},
                                 {QStringLiteral("region"), l.region},
                                 {QStringLiteral("city"), l.city},
                                 {QStringLiteral("isp"), l.isp},
                                 {QStringLiteral("org"), l.org},
                                 {QStringLiteral("asn"), l.asn},
                                 {QStringLiteral("timezone"), l.timezone}});
    root.insert(QStringLiteral("ipLocation"), ipArr);

    QJsonArray portsArr;
    for (const PortResult &p : m_ports)
        portsArr.append(QJsonObject{{QStringLiteral("host"), p.host},
                                    {QStringLiteral("port"), p.port},
                                    {QStringLiteral("service"), p.service},
                                    {QStringLiteral("banner"), p.banner}});
    root.insert(QStringLiteral("ports"), portsArr);

    QJsonArray cdnArr;
    for (const CdnRecord &c : m_cdnRecords)
        cdnArr.append(QJsonObject{{QStringLiteral("host"), c.host},
                                  {QStringLiteral("ip"), c.ip},
                                  {QStringLiteral("category"), c.category},
                                  {QStringLiteral("vendor"), c.vendor},
                                  {QStringLiteral("cname"), c.cname},
                                  {QStringLiteral("realIp"), c.realIp},
                                  {QStringLiteral("reason"), c.reason}});
    root.insert(QStringLiteral("cdn"), cdnArr);

    QJsonArray fingerArr;
    for (const WebFingerprint &w : m_fingerprints)
        fingerArr.append(QJsonObject{{QStringLiteral("url"), w.url},
                                     {QStringLiteral("status"), w.statusCode},
                                     {QStringLiteral("title"), w.title},
                                     {QStringLiteral("server"), w.server},
                                     {QStringLiteral("poweredBy"), w.poweredBy},
                                     {QStringLiteral("technologies"), w.technologies},
                                     {QStringLiteral("waf"), w.waf},
                                     {QStringLiteral("vulnHint"), w.vulnHint}});
    root.insert(QStringLiteral("fingerprints"), fingerArr);

    QJsonArray dirArr;
    for (const DirRecord &d : m_dirs)
        dirArr.append(QJsonObject{{QStringLiteral("url"), d.url},
                                  {QStringLiteral("status"), d.statusCode},
                                  {QStringLiteral("length"), d.length},
                                  {QStringLiteral("contentType"), d.contentType},
                                  {QStringLiteral("note"), d.note}});
    root.insert(QStringLiteral("directories"), dirArr);

    QJsonArray urlArr;
    for (const UrlRecord &u : m_urls)
        urlArr.append(QJsonObject{{QStringLiteral("url"), u.url},
                                  {QStringLiteral("status"), u.statusCode},
                                  {QStringLiteral("contentType"), u.contentType},
                                  {QStringLiteral("length"), u.length},
                                  {QStringLiteral("source"), u.source}});
    root.insert(QStringLiteral("urls"), urlArr);

    QFile f(file);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, QStringLiteral("导出失败"), f.errorString());
        return;
    }
    f.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    f.close();
    QMessageBox::information(this, QStringLiteral("导出完成"), QStringLiteral("已导出：%1").arg(file));
}

void MainWindow::onAbout()
{
    QMessageBox::about(
        this, QStringLiteral("关于 SRC 信息收集工具"),
        QStringLiteral(
            "<h3>SRC 信息收集工具 v1.1</h3>"
            "<p>基于 Qt6 / C++17 的多线程信息收集客户端，包含：</p>"
            "<ul>"
            "<li>子域名枚举：证书透明日志（crt.sh）+ 字典 DNS 爆破，含泛解析检测</li>"
            "<li>基础资产信息：Whois、ICP 备案、IP 归属地</li>"
            "<li>CDN / WAF 识别：CNAME 链与响应头签名判定 CDN/WAF 厂商，跳过边缘 IP、探测源站候选并聚合资产</li>"
            "<li>端口与服务扫描：按 IP 聚合去重，常见端口 / 自定义范围，Banner 指纹识别</li>"
            "<li>Web 指纹识别：标题、Server、中间件、CMS、框架，附 WAF 与版本漏洞线索</li>"
            "<li>目录与敏感路径探测：内置字典并发探测、通配响应检测</li>"
            "<li>爬虫与链接收集：广度优先抓取，提取链接 / JS 资产，并从 JS 中提取 API 接口与敏感信息</li>"
            "</ul>"
            "<p style=\"color:#c0392b;\">仅限用于已获得合法授权的安全测试与 SRC 众测场景，"
            "请勿对未授权目标使用。</p>"));
}

} // namespace src
