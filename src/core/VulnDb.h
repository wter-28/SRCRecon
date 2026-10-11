#pragma once

#include <QByteArray>
#include <QString>

/// 漏洞线索库（启发式）。以下结果均基于技术栈关键字与版本号区间推断，
/// **仅供参考 / 排查方向**，不作为漏洞存在性结论，需要人工进一步核实。
namespace src {
namespace vulndb {

/// 依据技术栈字符串、版本号与页面内容，给出已知漏洞线索（启发式，仅供参考）。
/// 多条线索以换行符拼接返回；无命中返回空字符串。
QString vulnHints(const QString &tech, const QString &version, const QByteArray &body);

} // namespace vulndb
} // namespace src