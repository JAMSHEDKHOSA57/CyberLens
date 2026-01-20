#ifndef HISTORYMANAGER_H
#define HISTORYMANAGER_H

#include <QString>
#include <QList>

struct HistoryItem {
    QString item;
    int score;
    QString type; // "URL" or "File"
};

class HistoryManager
{
public:
    HistoryManager();
    void addItem(const QString& item, int score, const QString& type);
    QList<HistoryItem> getHistory() const;

private:
    QList<HistoryItem> history;
};

#endif // HISTORYMANAGER_H
