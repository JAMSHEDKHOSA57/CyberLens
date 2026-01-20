#include "reportgenerator.h"
#include <QFile>
#include <QTextStream>
#include <QDateTime>

ReportGenerator::ReportGenerator()
{
}

void ReportGenerator::generateReport(const QString& content)
{
    QString filename = "CyberLens_Report_" + QDateTime::currentDateTime().toString("yyyy-MM-dd_hh-mm-ss") + ".txt";
    QFile file(filename);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&file);
        out << "CyberLens Report\n";
        out << "Generated: " << QDateTime::currentDateTime().toString() << "\n\n";
        out << content;
        file.close();
    }
}
