#ifndef URLANALYZER_H
#define URLANALYZER_H

#include <QString>

class UrlAnalyzer {
public:
    UrlAnalyzer();
    int analyzeOffline(const QString& url);  // Returns risk score 0-100
};

#endif // URLANALYZER_H
