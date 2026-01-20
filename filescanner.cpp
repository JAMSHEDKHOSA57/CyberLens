#include "filescanner.h"
#include <QCryptographicHash>
#include <QFile>

FileScanner::FileScanner() {
}

QString FileScanner::computeSHA256(const QString& filePath) {
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) return "Error opening file";

    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(&file);
    return hash.result().toHex();
}

QString FileScanner::getVerdict(const QString& hash) {
    // Known bad hash (EICAR test file)
    if (hash == "44d88612fea8a8f36de82e1278abb02f") {
        return "Malicious (EICAR Test)";
    }
    return "Clean";
}
