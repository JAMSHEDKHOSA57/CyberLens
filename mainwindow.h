#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QNetworkAccessManager>
#include <QTimer>
#include <QSet>
#include <QDateTime>
#include <QElapsedTimer>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

protected:
    void dragEnterEvent(QDragEnterEvent *event) override;
    void dropEvent(QDropEvent *event) override;

private slots:
    void on_btnAnalyzeUrl_clicked();
    void on_btnBrowse_clicked();
    void on_historyBtn_clicked();
    void on_reportBtn_clicked();

    void updateNetworkStatus();
    void loadOpenPhishFeed();

private:
    Ui::MainWindow *ui;

    // Network & timers
    QNetworkAccessManager *networkManager = nullptr;
    QTimer *networkTimer = nullptr;
    QTimer *openPhishTimer = nullptr;

    // State
    bool isOnline = false;
    bool openPhishLoaded = false;

    // Last scan info
    QString lastScannedUrl;
    QString lastScannedHash;

    QDateTime lastOpenPhishUpdate;
    QElapsedTimer networkCheckTimer;

    // OpenPhish storage (fast lookup)
    QSet<QString> openPhishUrls;
    QSet<QString> openPhishDomains;

    // Simple cache for recent VT file results (avoid spamming API)
    struct FileCacheItem {
        QString hash;
        int detections = -1;
        QDateTime lastCheck;
    };
    FileCacheItem fileCache;

    // ─── Private helper functions ───────────────────────────────────────
    QString computeSHA256(const QString &filePath);
    QString sanitizeUrl(const QString &input);
    int offlineUrlScore(const QString &url);
    void analyzeUrlOnline(const QString &url);
    void finishUrlAnalysis(int score, const QString &extraInfo = "");
    void performFileAnalysis(const QString &filePath, const QString &hash);
    void parseOpenPhishData(const QByteArray &data);
    bool isInOpenPhish(const QString &url);
};

#endif // MAINWINDOW_H
