#pragma once

#include <QFile>
#include <QHash>
#include <QStringList>
#include <QTextStream>
#include <QVector>

#include <QStringConverter>

/// 内置字典与常见端口表。用户可在界面中指定外部字典文件覆盖。
namespace src {
namespace words {

/// 常见子域名字典
inline const QStringList &subdomains()
{
    static const QStringList w = {
        QStringLiteral("www"), QStringLiteral("mail"), QStringLiteral("webmail"),
        QStringLiteral("smtp"), QStringLiteral("pop"), QStringLiteral("pop3"),
        QStringLiteral("imap"), QStringLiteral("mx"), QStringLiteral("ns1"),
        QStringLiteral("ns2"), QStringLiteral("ns3"), QStringLiteral("dns"),
        QStringLiteral("dns1"), QStringLiteral("dns2"), QStringLiteral("ftp"),
        QStringLiteral("sftp"), QStringLiteral("ssh"), QStringLiteral("vpn"),
        QStringLiteral("remote"), QStringLiteral("portal"), QStringLiteral("oa"),
        QStringLiteral("crm"), QStringLiteral("erp"), QStringLiteral("hr"),
        QStringLiteral("mail2"), QStringLiteral("web"), QStringLiteral("api"),
        QStringLiteral("apis"), QStringLiteral("open"), QStringLiteral("openapi"),
        QStringLiteral("gateway"), QStringLiteral("gw"), QStringLiteral("auth"),
        QStringLiteral("sso"), QStringLiteral("login"), QStringLiteral("oauth"),
        QStringLiteral("id"), QStringLiteral("account"), QStringLiteral("user"),
        QStringLiteral("admin"), QStringLiteral("manage"), QStringLiteral("manager"),
        QStringLiteral("console"), QStringLiteral("dashboard"), QStringLiteral("panel"),
        QStringLiteral("cpanel"), QStringLiteral("sys"), QStringLiteral("system"),
        QStringLiteral("ops"), QStringLiteral("monitor"), QStringLiteral("status"),
        QStringLiteral("grafana"), QStringLiteral("kibana"), QStringLiteral("zabbix"),
        QStringLiteral("nagios"), QStringLiteral("prometheus"), QStringLiteral("alert"),
        QStringLiteral("log"), QStringLiteral("logs"), QStringLiteral("elk"),
        QStringLiteral("git"), QStringLiteral("gitlab"), QStringLiteral("github"),
        QStringLiteral("gitea"), QStringLiteral("svn"), QStringLiteral("jenkins"),
        QStringLiteral("ci"), QStringLiteral("cd"), QStringLiteral("build"),
        QStringLiteral("repo"), QStringLiteral("nexus"), QStringLiteral("harbor"),
        QStringLiteral("registry"), QStringLiteral("docker"), QStringLiteral("k8s"),
        QStringLiteral("kube"), QStringLiteral("rancher"), QStringLiteral("consul"),
        QStringLiteral("etcd"), QStringLiteral("zookeeper"), QStringLiteral("mq"),
        QStringLiteral("rabbitmq"), QStringLiteral("kafka"), QStringLiteral("redis"),
        QStringLiteral("mysql"), QStringLiteral("db"), QStringLiteral("database"),
        QStringLiteral("oracle"), QStringLiteral("mssql"), QStringLiteral("pg"),
        QStringLiteral("postgres"), QStringLiteral("mongo"), QStringLiteral("es"),
        QStringLiteral("search"), QStringLiteral("solr"), QStringLiteral("elastic"),
        QStringLiteral("cache"), QStringLiteral("memcache"), QStringLiteral("session"),
        QStringLiteral("ftp2"), QStringLiteral("files"), QStringLiteral("file"),
        QStringLiteral("fs"), QStringLiteral("nas"), QStringLiteral("backup"),
        QStringLiteral("bak"), QStringLiteral("archive"), QStringLiteral("data"),
        QStringLiteral("download"), QStringLiteral("downloads"), QStringLiteral("up"),
        QStringLiteral("upload"), QStringLiteral("uploads"), QStringLiteral("static"),
        QStringLiteral("assets"), QStringLiteral("img"), QStringLiteral("images"),
        QStringLiteral("image"), QStringLiteral("cdn"), QStringLiteral("res"),
        QStringLiteral("resource"), QStringLiteral("media"), QStringLiteral("video"),
        QStringLiteral("videoapi"), QStringLiteral("live"), QStringLiteral("stream"),
        QStringLiteral("push"), QStringLiteral("msg"), QStringLiteral("message"),
        QStringLiteral("im"), QStringLiteral("chat"), QStringLiteral("help"),
        QStringLiteral("support"), QStringLiteral("service"), QStringLiteral("kf"),
        QStringLiteral("customer"), QStringLiteral("cms"), QStringLiteral("blog"),
        QStringLiteral("news"), QStringLiteral("wiki"), QStringLiteral("doc"),
        QStringLiteral("docs"), QStringLiteral("dev"), QStringLiteral("developer"),
        QStringLiteral("staging"), QStringLiteral("stage"), QStringLiteral("test"),
        QStringLiteral("testing"), QStringLiteral("uat"), QStringLiteral("pre"),
        QStringLiteral("preprod"), QStringLiteral("demo"), QStringLiteral("sandbox"),
        QStringLiteral("beta"), QStringLiteral("alpha"), QStringLiteral("release"),
        QStringLiteral("old"), QStringLiteral("new"), QStringLiteral("vpn2"),
        QStringLiteral("proxy"), QStringLiteral("gate"), QStringLiteral("firewall"),
        QStringLiteral("fw"), QStringLiteral("router"), QStringLiteral("switch"),
        QStringLiteral("idc"), QStringLiteral("host"), QStringLiteral("server"),
        QStringLiteral("srv"), QStringLiteral("node"), QStringLiteral("node1"),
        QStringLiteral("node2"), QStringLiteral("app"), QStringLiteral("apps"),
        QStringLiteral("m"), QStringLiteral("mobile"), QStringLiteral("wap"),
        QStringLiteral("h5"), QStringLiteral("web2"), QStringLiteral("pay"),
        QStringLiteral("payment"), QStringLiteral("cashier"), QStringLiteral("order"),
        QStringLiteral("shop"), QStringLiteral("mall"), QStringLiteral("store"),
        QStringLiteral("market"), QStringLiteral("trade"), QStringLiteral("finance"),
        QStringLiteral("bank"), QStringLiteral("fund"), QStringLiteral("report"),
        QStringLiteral("bi"), QStringLiteral("dw"), QStringLiteral("etl"),
        QStringLiteral("insight"), QStringLiteral("analysis"), QStringLiteral("scm"),
        QStringLiteral("wms"), QStringLiteral("tms"), QStringLiteral("mes"),
        QStringLiteral("plm"), QStringLiteral("pdm"), QStringLiteral("bpm"),
        QStringLiteral("flow"), QStringLiteral("workflow"), QStringLiteral("form"),
        QStringLiteral("report2"), QStringLiteral("sms"), QStringLiteral("email"),
        QStringLiteral("mailer"), QStringLiteral("newsletter"), QStringLiteral("stats"),
        QStringLiteral("stat"), QStringLiteral("analytics"), QStringLiteral("track"),
        QStringLiteral("tracking"), QStringLiteral("ads"), QStringLiteral("ad"),
        QStringLiteral("seo"), QStringLiteral("sem"), QStringLiteral("dm"),
        QStringLiteral("member"), QStringLiteral("vip"), QStringLiteral("agent"),
        QStringLiteral("partner"), QStringLiteral("supplier"), QStringLiteral("vendor"),
        QStringLiteral("third"), QStringLiteral("thirdparty"), QStringLiteral("extranet"),
        QStringLiteral("intranet"), QStringLiteral("internal"), QStringLiteral("office"),
        QStringLiteral("meeting"), QStringLiteral("vc"), QStringLiteral("conference"),
        QStringLiteral("edu"), QStringLiteral("learn"), QStringLiteral("study"),
        QStringLiteral("train"), QStringLiteral("exam"), QStringLiteral("lms"),
        QStringLiteral("mt"), QStringLiteral("mta"), QStringLiteral("relay"),
        QStringLiteral("mx1"), QStringLiteral("mx2"), QStringLiteral("bbs"),
        QStringLiteral("forum"), QStringLiteral("community"), QStringLiteral("club"),
        QStringLiteral("game"), QStringLiteral("games"), QStringLiteral("open2"),
        QStringLiteral("idp"), QStringLiteral("cas"), QStringLiteral("ldap"),
        QStringLiteral("ad"), QStringLiteral("dc"), QStringLiteral("dc1"),
        QStringLiteral("dc2"), QStringLiteral("share"), QStringLiteral("sharepoint"),
        QStringLiteral("exchange"), QStringLiteral("owa"), QStringLiteral("lync"),
        QStringLiteral("skype"), QStringLiteral("meet"), QStringLiteral("zoom"),
        QStringLiteral("teams"), QStringLiteral("drive"), QStringLiteral("cloud"),
        QStringLiteral("pan"), QStringLiteral("disk"), QStringLiteral("sync"),
        QStringLiteral("passport"), QStringLiteral("uc"), QStringLiteral("appapi")
    };
    return w;
}

/// 常见目录 / 敏感路径字典
inline const QStringList &directories()
{
    static const QStringList w = {
        QStringLiteral("robots.txt"), QStringLiteral("sitemap.xml"),
        QStringLiteral("crossdomain.xml"), QStringLiteral("security.txt"),
        QStringLiteral(".git/config"), QStringLiteral(".git/HEAD"),
        QStringLiteral(".svn/entries"), QStringLiteral(".env"),
        QStringLiteral(".env.bak"), QStringLiteral(".DS_Store"),
        QStringLiteral("admin/"), QStringLiteral("administrator/"),
        QStringLiteral("manage/"), QStringLiteral("manager/"),
        QStringLiteral("login"), QStringLiteral("login.jsp"),
        QStringLiteral("login.php"), QStringLiteral("login.html"),
        QStringLiteral("logout"), QStringLiteral("register"),
        QStringLiteral("api/"), QStringLiteral("api/v1/"),
        QStringLiteral("api/v2/"), QStringLiteral("swagger-ui.html"),
        QStringLiteral("swagger-ui/"), QStringLiteral("swagger/index.html"),
        QStringLiteral("v2/api-docs"), QStringLiteral("v3/api-docs"),
        QStringLiteral("api-docs"), QStringLiteral("actuator"),
        QStringLiteral("actuator/health"), QStringLiteral("actuator/env"),
        QStringLiteral("actuator/beans"), QStringLiteral("actuator/mappings"),
        QStringLiteral("heapdump"), QStringLiteral("env"),
        QStringLiteral("config"), QStringLiteral("config.json"),
        QStringLiteral("config.js"), QStringLiteral("settings.py"),
        QStringLiteral("web.config"), QStringLiteral("phpinfo.php"),
        QStringLiteral("info.php"), QStringLiteral("test.php"),
        QStringLiteral("console"), QStringLiteral("druid/index.html"),
        QStringLiteral("druid/"), QStringLiteral("jenkins/"),
        QStringLiteral("jenkins/script"), QStringLiteral("grafana/"),
        QStringLiteral("kibana/"), QStringLiteral("zabbix/"),
        QStringLiteral("phpmyadmin/"), QStringLiteral("pma/"),
        QStringLiteral("adminer.php"), QStringLiteral("mysql/"),
        QStringLiteral("solr/"), QStringLiteral("elasticsearch/"),
        QStringLiteral("_cat/indices"), QStringLiteral("nacos/"),
        QStringLiteral("nacos/v1/auth/users"), QStringLiteral("eureka/"),
        QStringLiteral("backup"), QStringLiteral("backup.zip"),
        QStringLiteral("backup.sql"), QStringLiteral("db.sql"),
        QStringLiteral("dump.sql"), QStringLiteral("www.zip"),
        QStringLiteral("web.zip"), QStringLiteral("site.zip"),
        QStringLiteral("wwwroot.zip"), QStringLiteral("test.zip"),
        QStringLiteral("1.zip"), QStringLiteral("data.zip"),
        QStringLiteral("upload/"), QStringLiteral("uploads/"),
        QStringLiteral("files/"), QStringLiteral("file/"),
        QStringLiteral("download/"), QStringLiteral("downloads/"),
        QStringLiteral("static/"), QStringLiteral("assets/"),
        QStringLiteral("images/"), QStringLiteral("img/"),
        QStringLiteral("css/"), QStringLiteral("js/"),
        QStringLiteral("js/config.js"), QStringLiteral("js/app.js"),
        QStringLiteral("index.php"), QStringLiteral("index.jsp"),
        QStringLiteral("index.action"), QStringLiteral("index.html"),
        QStringLiteral("default.aspx"), QStringLiteral("home"),
        QStringLiteral("dashboard"), QStringLiteral("portal"),
        QStringLiteral("user/"), QStringLiteral("users/"),
        QStringLiteral("user/list"), QStringLiteral("account/"),
        QStringLiteral("member/"), QStringLiteral("system/"),
        QStringLiteral("sys/"), QStringLiteral("status"),
        QStringLiteral("server-status"), QStringLiteral("server-info"),
        QStringLiteral("nginx_status"), QStringLiteral("metrics"),
        QStringLiteral("health"), QStringLiteral("healthz"),
        QStringLiteral("version"), QStringLiteral("versions"),
        QStringLiteral("changelog"), QStringLiteral("README.md"),
        QStringLiteral("readme.txt"), QStringLiteral("LICENSE"),
        QStringLiteral("package.json"), QStringLiteral("composer.json"),
        QStringLiteral("webpack.config.js"), QStringLiteral("gulpfile.js"),
        QStringLiteral("Makefile"), QStringLiteral("Dockerfile"),
        QStringLiteral("docker-compose.yml"), QStringLiteral("Vagrantfile"),
        QStringLiteral(".htaccess"), QStringLiteral(".htpasswd"),
        QStringLiteral(".bash_history"), QStringLiteral(".ssh/id_rsa"),
        QStringLiteral("id_rsa"), QStringLiteral("wp-login.php"),
        QStringLiteral("wp-admin/"), QStringLiteral("wp-config.php.bak"),
        QStringLiteral("xmlrpc.php"), QStringLiteral("dede/"),
        QStringLiteral("plus/"), QStringLiteral("uc_server/"),
        QStringLiteral("install/"), QStringLiteral("install.php"),
        QStringLiteral("setup/"), QStringLiteral("upgrade/"),
        QStringLiteral("phpMyAdmin/"), QStringLiteral("resin/"),
        QStringLiteral("weblogic/"), QStringLiteral("console/login/LoginForm.jsp"),
        QStringLiteral("manager/html"), QStringLiteral("host-manager/html"),
        QStringLiteral("examples/"), QStringLiteral("docs/"),
        QStringLiteral("doc/"), QStringLiteral("help/"),
        QStringLiteral("error"), QStringLiteral("403"),
        QStringLiteral("404"), QStringLiteral("500"),
        QStringLiteral("crossdomain.xml"), QStringLiteral("clientaccesspolicy.xml")
    };
    return w;
}

/// 常见端口列表（用于 common 模式）
inline const QVector<int> &commonPorts()
{
    static const QVector<int> p = {
        21, 22, 23, 25, 53, 67, 68, 69, 80, 81, 82, 83, 84, 85, 88, 89,
        110, 111, 123, 135, 137, 138, 139, 143, 161, 162, 179, 389, 443,
        445, 465, 500, 514, 515, 520, 548, 554, 587, 623, 631, 636, 646,
        873, 902, 990, 993, 995, 1025, 1080, 1099, 1158, 1433, 1434, 1521,
        1701, 1723, 1883, 1900, 2049, 2082, 2083, 2181, 2222, 2375, 2376,
        2480, 3000, 3128, 3260, 3306, 3389, 3478, 3690, 4000, 4443, 4505,
        4506, 5000, 5001, 5432, 5555, 5601, 5672, 5900, 5901, 5984, 6000,
        6379, 6443, 7001, 7002, 7070, 7171, 7443, 8000, 8001, 8008, 8009,
        8010, 8030, 8069, 8080, 8081, 8082, 8083, 8088, 8090, 8091, 8161,
        8180, 8200, 8443, 8500, 8529, 8761, 8834, 8888, 8983, 9000, 9001,
        9042, 9060, 9090, 9091, 9092, 9100, 9160, 9200, 9300, 9443, 9500,
        9600, 9999, 10000, 10250, 11211, 15672, 16379, 27017, 27018, 28017,
        50000, 50070, 50075, 61616
    };
    return p;
}

/// 端口 -> 常见服务名
inline QString serviceByPort(int port)
{
    static const QHash<int, QString> m = {
        {21, QStringLiteral("FTP")}, {22, QStringLiteral("SSH")},
        {23, QStringLiteral("Telnet")}, {25, QStringLiteral("SMTP")},
        {53, QStringLiteral("DNS")}, {69, QStringLiteral("TFTP")},
        {80, QStringLiteral("HTTP")}, {110, QStringLiteral("POP3")},
        {111, QStringLiteral("RPCBind")}, {135, QStringLiteral("MSRPC")},
        {139, QStringLiteral("NetBIOS")}, {143, QStringLiteral("IMAP")},
        {161, QStringLiteral("SNMP")}, {389, QStringLiteral("LDAP")},
        {443, QStringLiteral("HTTPS")}, {445, QStringLiteral("SMB")},
        {465, QStringLiteral("SMTPS")}, {514, QStringLiteral("Syslog")},
        {548, QStringLiteral("AFP")}, {587, QStringLiteral("SMTP-Submission")},
        {636, QStringLiteral("LDAPS")}, {873, QStringLiteral("Rsync")},
        {993, QStringLiteral("IMAPS")}, {995, QStringLiteral("POP3S")},
        {1080, QStringLiteral("SOCKS")}, {1433, QStringLiteral("MSSQL")},
        {1521, QStringLiteral("Oracle")}, {1723, QStringLiteral("PPTP")},
        {1883, QStringLiteral("MQTT")}, {2049, QStringLiteral("NFS")},
        {2181, QStringLiteral("ZooKeeper")}, {2375, QStringLiteral("Docker")},
        {2376, QStringLiteral("Docker-TLS")}, {3000, QStringLiteral("Node/Grafana")},
        {3128, QStringLiteral("Squid")}, {3306, QStringLiteral("MySQL")},
        {3389, QStringLiteral("RDP")}, {3690, QStringLiteral("SVN")},
        {4443, QStringLiteral("HTTPS-Alt")}, {4505, QStringLiteral("SaltStack")},
        {5000, QStringLiteral("Flask/UPnP")}, {5432, QStringLiteral("PostgreSQL")},
        {5601, QStringLiteral("Kibana")}, {5672, QStringLiteral("RabbitMQ")},
        {5900, QStringLiteral("VNC")}, {5984, QStringLiteral("CouchDB")},
        {6379, QStringLiteral("Redis")}, {6443, QStringLiteral("K8s-API")},
        {7001, QStringLiteral("WebLogic")}, {7002, QStringLiteral("WebLogic-SSL")},
        {8000, QStringLiteral("HTTP-Alt")}, {8009, QStringLiteral("AJP")},
        {8080, QStringLiteral("HTTP-Proxy/Tomcat")}, {8081, QStringLiteral("HTTP-Alt")},
        {8088, QStringLiteral("HTTP-Alt")}, {8161, QStringLiteral("ActiveMQ")},
        {8443, QStringLiteral("HTTPS-Alt")}, {8500, QStringLiteral("Consul")},
        {8529, QStringLiteral("ArangoDB")}, {8761, QStringLiteral("Eureka")},
        {8888, QStringLiteral("HTTP-Alt")}, {8983, QStringLiteral("Solr")},
        {9000, QStringLiteral("PHP-FPM/Sonar")}, {9042, QStringLiteral("Cassandra")},
        {9090, QStringLiteral("WebSphere/Cockpit")}, {9092, QStringLiteral("Kafka")},
        {9100, QStringLiteral("Printer")}, {9200, QStringLiteral("Elasticsearch")},
        {9300, QStringLiteral("ES-Transport")}, {9443, QStringLiteral("HTTPS-Alt")},
        {9999, QStringLiteral("HTTP-Alt")}, {10000, QStringLiteral("Webmin")},
        {10250, QStringLiteral("Kubelet")}, {11211, QStringLiteral("Memcached")},
        {15672, QStringLiteral("RabbitMQ-UI")}, {27017, QStringLiteral("MongoDB")},
        {50070, QStringLiteral("HDFS")}, {61616, QStringLiteral("ActiveMQ")}
    };
    return m.value(port, QStringLiteral("unknown"));
}

/// 读取外部字典文件（每行一个条目，# 开头为注释）；失败时回退到内置字典
inline QStringList loadWordlist(const QString &filePath, const QStringList &fallback)
{
    if (filePath.trimmed().isEmpty())
        return fallback;

    QFile f(filePath);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return fallback;

    QStringList out;
    QTextStream in(&f);
    in.setEncoding(QStringConverter::Utf8);
    while (!in.atEnd()) {
        const QString line = in.readLine().trimmed();
        if (line.isEmpty() || line.startsWith(QLatin1Char('#')))
            continue;
        out << line;
    }
    return out.isEmpty() ? fallback : out;
}

} // namespace words
} // namespace src
