#include "urlanalyzer.h"
#include <QRegularExpression>

UrlAnalyzer::UrlAnalyzer() {
}

int UrlAnalyzer::analyzeOffline(const QString& url) {
    if (url.trimmed().isEmpty()) return 0;

    int score = 0;
    QString lower = url.toLower();

    // Suspicious keywords
    QStringList keywords = {"login", "secure", "bank", "paypal", "verify", "account", "update", "free", "prize", "password", "urgent", "click", "winner"};
    for (const QString& word : keywords) {
        if (lower.contains(word)) score += 20;
    }

    // Long URL
    if (url.length() > 100) score += 40;
    else if (url.length() > 70) score += 20;

    // Special characters like @
    if (url.count("@") > 0) score += 30;

    // Suspicious TLDs
    if (lower.endsWith(".tk") || lower.endsWith(".ml") || lower.endsWith(".ga") || lower.endsWith(".cf") || lower.endsWith(".gq")) {
        score += 30;
    }

    // Cap at 100
    if (score > 100) score = 100;

    return score;
}
