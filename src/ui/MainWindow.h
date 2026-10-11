#pragma once

#include <QMainWindow>
#include <QVector>

#include "core/EngineOptions.h"
#include "core/Types.h"

class QLineEdit;
class QSpinBox;
class QCheckBox;
class QPushButton;
class QTabWidget;
class QTableWidget;
class QPlainTextEdit;
class QProgressBar;
class QLabel;
class QCloseEvent;

namespace src {

class ReconEngine;

/// 主窗口：左侧参数配置，右侧分页展示各类收集结果
class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

protected:
    void closeEvent(QCloseEvent *event) override;

private slots:
    void onStart();
    void onStop();
    void onBrowseSubdomainDict();
    void onBrowseDirDict();
    void onExportCsv();
    void onExportJson();
    void onAbout();

    void onEngineStarted();
    void onEngineFinished(bool ok, const QString &summary);
    void onLog(const QString &level, const QString &text);
    void onStage(const QString &stage, int index, int count);
    void onProgress(int done, int total);

    void onSubdomains(const src::DomainAssetList &items);
    void onWhois(const src::WhoisInfo &info);
    void onIcp(const src::IcpInfo &info);
    void onIpLocation(const src::IpLocation &info);
    void onPorts(const src::PortResultList &items);
    void onFingerprints(const src::WebFingerprintList &items);
    void onDirs(const src::DirRecordList &items);
    void onUrls(const src::UrlRecordList &items);
    void onCdn(const src::CdnRecordList &items);

private:
    void buildUi();
    void buildMenu();
    QWidget *buildSidePanel();
    QWidget *buildResultTabs();

    void collectOptions(EngineOptions &opt) const;
    void applyOptions(const EngineOptions &opt);
    void setBusy(bool busy);
    void clearResults();
    void updateTabTitles();
    void refreshAssetTable();
    void appendLog(const QString &level, const QString &text);

    // 输入控件
    QLineEdit *m_targetEdit = nullptr;
    QCheckBox *m_demoCheck = nullptr;
    QCheckBox *m_cbSub = nullptr;
    QCheckBox *m_cbCdn = nullptr;
    QCheckBox *m_cbAsset = nullptr;
    QCheckBox *m_cbPort = nullptr;
    QCheckBox *m_cbFinger = nullptr;
    QCheckBox *m_cbDir = nullptr;
    QCheckBox *m_cbCrawl = nullptr;
    QSpinBox *m_threadsSpin = nullptr;
    QSpinBox *m_timeoutSpin = nullptr;
    QLineEdit *m_portSpecEdit = nullptr;
    QLineEdit *m_subDictEdit = nullptr;
    QLineEdit *m_dirDictEdit = nullptr;
    QSpinBox *m_crawlPagesSpin = nullptr;
    QSpinBox *m_crawlDepthSpin = nullptr;
    QCheckBox *m_crawlExternalCheck = nullptr;
    QLineEdit *m_icpApiEdit = nullptr;
    QPushButton *m_startBtn = nullptr;
    QPushButton *m_stopBtn = nullptr;

    // 结果控件
    QTabWidget *m_tabs = nullptr;
    QTableWidget *m_subTable = nullptr;
    QTableWidget *m_assetTable = nullptr;
    QTableWidget *m_cdnTable = nullptr;
    QTableWidget *m_portTable = nullptr;
    QTableWidget *m_fingerTable = nullptr;
    QTableWidget *m_dirTable = nullptr;
    QTableWidget *m_urlTable = nullptr;
    QPlainTextEdit *m_logView = nullptr;

    QLabel *m_stageLabel = nullptr;
    QProgressBar *m_progress = nullptr;

    ReconEngine *m_engine = nullptr;

    // 结构化结果数据（同时用于表格展示与导出）
    DomainAssetList    m_subdomains;
    CdnRecordList      m_cdnRecords;
    PortResultList     m_ports;
    WebFingerprintList m_fingerprints;
    DirRecordList      m_dirs;
    UrlRecordList      m_urls;
    QVector<WhoisInfo> m_whoisList;
    QVector<IcpInfo>   m_icpList;
    QVector<IpLocation> m_ipList;
};

} // namespace src
