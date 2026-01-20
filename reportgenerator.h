#ifndef REPORTGENERATOR_H
#define REPORTGENERATOR_H

#include <QString>

class ReportGenerator
{
public:
    ReportGenerator();
    void generateReport(const QString& content);
};

#endif // REPORTGENERATOR_H
