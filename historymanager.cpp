#include "historymanager.h"

HistoryManager::HistoryManager()
{
}

void HistoryManager::addItem(const QString& item, int score, const QString& type)
{
    HistoryItem h;
    h.item = item;
    h.score = score;
    h.type = type;
    history.append(h);
}

QList<HistoryItem> HistoryManager::getHistory() const
{
    return history;
}
