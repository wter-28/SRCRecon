#include <QApplication>
#include <QFont>

#include "core/Types.h"
#include "ui/MainWindow.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("SRCRecon"));
    QApplication::setOrganizationName(QStringLiteral("SRCRecon"));
    QApplication::setApplicationVersion(QStringLiteral("1.2.0"));

    // 注册自定义类型，保证跨线程队列信号可以正常投递
    qRegisterMetaType<src::DomainAsset>("src::DomainAsset");
    qRegisterMetaType<src::WhoisInfo>("src::WhoisInfo");
    qRegisterMetaType<src::IcpInfo>("src::IcpInfo");
    qRegisterMetaType<src::IpLocation>("src::IpLocation");
    qRegisterMetaType<src::PortResult>("src::PortResult");
    qRegisterMetaType<src::WebFingerprint>("src::WebFingerprint");
    qRegisterMetaType<src::DirRecord>("src::DirRecord");
    qRegisterMetaType<src::UrlRecord>("src::UrlRecord");
    qRegisterMetaType<src::CdnRecord>("src::CdnRecord");
    qRegisterMetaType<src::AssetSummary>("src::AssetSummary");
    qRegisterMetaType<src::DomainAssetList>("src::DomainAssetList");
    qRegisterMetaType<src::PortResultList>("src::PortResultList");
    qRegisterMetaType<src::WebFingerprintList>("src::WebFingerprintList");
    qRegisterMetaType<src::DirRecordList>("src::DirRecordList");
    qRegisterMetaType<src::UrlRecordList>("src::UrlRecordList");
    qRegisterMetaType<src::CdnRecordList>("src::CdnRecordList");
    qRegisterMetaType<src::ApiEndpointList>("src::ApiEndpointList");
    qRegisterMetaType<src::AssetSummaryList>("src::AssetSummaryList");

    QFont font = app.font();
    font.setFamily(QStringLiteral("Microsoft YaHei UI"));
    font.setPointSize(9);
    app.setFont(font);

    src::MainWindow window;
    window.show();

    return app.exec();
}
