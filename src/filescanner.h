#ifndef FILESCANNER_H
#define FILESCANNER_H

#include <QString>

class FileScanner {
public:
    FileScanner();
    QString computeSHA256(const QString& filePath);
    QString getVerdict(const QString& hash);  // Basic verdict based on hash
};

#endif // FILESCANNER_H
