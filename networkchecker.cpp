#include "networkchecker.h"
#include <QNetworkInterface>

NetworkChecker::NetworkChecker() {
}

bool NetworkChecker::isOnline() {
    QList<QNetworkInterface> interfaces = QNetworkInterface::allInterfaces();
    for (const QNetworkInterface& interface : interfaces) {
        if (interface.flags().testFlag(QNetworkInterface::IsUp) && !interface.flags().testFlag(QNetworkInterface::IsLoopBack)) {
            return true;
        }
    }
    return false;
}
