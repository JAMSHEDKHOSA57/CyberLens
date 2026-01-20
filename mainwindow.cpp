#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QCryptographicHash>
#include <QFile>
#include <QDateTime>
#include <QTextStream>
#include <QStandardPaths>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QRegularExpression>
#include <QUrl>
#include <QUrlQuery>
#include <QDebug>
#include <QDragEnterEvent>
#include <QMimeData>
#include <memory>


#include <QVector>

// Minimal history structure (used only for logging)
struct HistoryItem {
    QString type;
    QString item;
    QString result;
};

// Global history container (kept in cpp only)
static QVector<HistoryItem> historyList;

// ────────────────────────────────────────────────
//          Your API keys are defined here
// ────────────────────────────────────────────────
static const char* VT_API_KEY  = "c787f55fb03634bb52ffc6008ffbb41f8bc0f839f754e70aac8309d39d4966e7";
static const char* GSB_API_KEY = "AIzaSyBTqM5T-XBUD_Iv6RMV0svazqZHJHLZUa4";

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setAcceptDrops(true);
    networkManager = new QNetworkAccessManager(this);
    networkTimer = new QTimer(this);
    connect(networkTimer, &QTimer::timeout, this, &MainWindow::updateNetworkStatus);
    networkTimer->start(10000);
    updateNetworkStatus();
    openPhishTimer = new QTimer(this);
    connect(openPhishTimer, &QTimer::timeout, this, &MainWindow::loadOpenPhishFeed);
    openPhishTimer->start(3600000);
    lastScannedUrl = "";
    lastScannedHash = "";
    lastOpenPhishUpdate = QDateTime();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData()->hasUrls()) {
        event->acceptProposedAction();
    }
}

void MainWindow::dropEvent(QDropEvent *event)
{
    if (event->mimeData()->hasUrls()) {
        QString filePath = event->mimeData()->urls().first().toLocalFile();
        if (!filePath.isEmpty() && QFile::exists(filePath)) {
            QString hash = computeSHA256(filePath);
            if (hash.isEmpty()) {
                QMessageBox::warning(this, "Error", "Cannot read dropped file.");
                return;
            }
            lastScannedHash = hash;
            lastScannedUrl = "";
            ui->hashLabel->setText("SHA-256: " + hash.left(20) + "...");
            performFileAnalysis(filePath, hash);
        }
        event->acceptProposedAction();
    }
}

void MainWindow::updateNetworkStatus()
{
    networkCheckTimer.restart();
    ui->modeLabel->setText("🔄 Checking connection...");
    ui->modeLabel->setStyleSheet("color:orange; font-weight:bold;");
    QNetworkRequest request(QUrl("http://clients3.google.com/generate_204"));
    request.setTransferTimeout(5000);
    QNetworkReply *reply = networkManager->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        bool online =
            reply->error() == QNetworkReply::NoError &&
            reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() == 204;
        int elapsed = networkCheckTimer.elapsed();
        int minDisplayTime = 1500;
        int delay = qMax(0, minDisplayTime - elapsed);
        QTimer::singleShot(delay, this, [this, online]() {
            isOnline = online;
            if (isOnline) {
                ui->modeLabel->setText("🟢 ONLINE MODE");
                ui->modeLabel->setStyleSheet("color:#4ade80; font-weight:bold;");
                if (!openPhishLoaded) {
                    loadOpenPhishFeed();
                }
            } else {
                ui->modeLabel->setText("🔴 OFFLINE MODE ");
                ui->modeLabel->setStyleSheet("color:red; font-weight:bold;");
            }
        });
        reply->deleteLater();
    });
}

QString MainWindow::computeSHA256(const QString &filePath)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return "";
    }
    QCryptographicHash hash(QCryptographicHash::Sha256);
    if (hash.addData(&file)) {
        file.close();
        return hash.result().toHex();
    }
    file.close();
    return "";
}
QString MainWindow::sanitizeUrl(const QString &input)
{
    QString url = input.trimmed();

    // Remove dangerous whitespace and control chars
    url.remove(QRegularExpression("[\\x00-\\x1F\\x7F]"));

    // Fix double protocol issue
    if (url.startsWith("https://http://"))
        url = url.mid(8);
    if (url.startsWith("http://https://"))
        url = url.mid(7);

    // Enforce scheme
    if (!url.startsWith("http://") && !url.startsWith("https://"))
        url = "https://" + url;

    QUrl qurl(url);
    if (!qurl.isValid() || qurl.host().isEmpty())
        return "";

    return qurl.toString(QUrl::FullyEncoded);
}


int MainWindow::offlineUrlScore(const QString &url)
{
    int score = 5;
    QString lower = url.toLower();
    if (lower.contains("login") || lower.contains("verify") || lower.contains("secure") ||
        lower.contains("account") || lower.contains("update") || lower.contains("password") ||
        lower.contains("bank") || lower.contains("paypal") || lower.contains("amazon"))
        score += 40;
    if (url.length() > 75) score += 20;
    if (url.count(".") > 4) score += 25;
    if (url.contains("@")) score += 35;
    QRegularExpression ipRegex(R"(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)");
    if (ipRegex.match(url).hasMatch()) score += 45;
    if (lower.contains("xn--")) score += 35;
    QStringList badTLDs = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".win", ".bid", ".loan"};
    for (const QString &tld : badTLDs) {
        if (lower.endsWith(tld)) {
            score += 40;
            break;
        }
    }
    if (url.startsWith("http://") && lower.contains("login")) score += 25;
    if (score > 100) score = 100;
    return score;
}

void MainWindow::analyzeUrlOnline(const QString &url)
{
    ui->urlRiskScore->setText("🔄 Analyzing (Heuristics + OpenPhish + APIs)...");
    ui->urlRiskScore->setStyleSheet("color:orange; font-weight:bold;");
    lastScannedUrl = url;
    lastScannedHash = "";
    int baseScore = offlineUrlScore(url);
    auto riskScorePtr = std::make_shared<int>(baseScore);
    bool openPhishMatch = isInOpenPhish(url);
    if (openPhishMatch) {
        *riskScorePtr = qMax(*riskScorePtr, 99);
    }
    auto finishedPtr = std::make_shared<bool>(false);
    auto finishOnce = [this, riskScorePtr, openPhishMatch, finishedPtr]() {
        if (!*finishedPtr) {
            *finishedPtr = true;
            QString extra = openPhishMatch ? " (Detected by OpenPhish blacklist)" : "";
            finishUrlAnalysis(*riskScorePtr, extra);
        }
    };

    // VirusTotal URL submission
    QNetworkRequest vtSubmit(QUrl("https://www.virustotal.com/api/v3/urls"));
    vtSubmit.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
    vtSubmit.setRawHeader("x-apikey", VT_API_KEY);
    QByteArray vtData = "url=" + QUrl::toPercentEncoding(url);
    QNetworkReply *vtReply = networkManager->post(vtSubmit, vtData);
    connect(vtReply, &QNetworkReply::finished, this, [this, vtReply, riskScorePtr, finishOnce]() {
        if (vtReply->error() == QNetworkReply::NoError) {
            QJsonDocument doc = QJsonDocument::fromJson(vtReply->readAll());
            QString analysisId = doc.object()["data"].toObject()["id"].toString();
            QTimer::singleShot(15000, this, [this, analysisId, riskScorePtr, finishOnce]() {
                QNetworkRequest report(QUrl("https://www.virustotal.com/api/v3/analyses/" + analysisId));
                report.setRawHeader("x-apikey", VT_API_KEY);
                QNetworkReply *r = networkManager->get(report);
                connect(r, &QNetworkReply::finished, this, [this, r, riskScorePtr, finishOnce]() {
                    if (r->error() == QNetworkReply::NoError) {
                        QJsonObject stats = QJsonDocument::fromJson(r->readAll())
                        .object()["data"].toObject()["attributes"].toObject()["stats"].toObject();
                        int malicious = stats["malicious"].toInt();
                        int suspicious = stats["suspicious"].toInt();
                        if (malicious + suspicious > 0) {
                            *riskScorePtr = qMax(*riskScorePtr, 95 + (malicious > 3 ? 5 : 0));
                        }
                    }
                    finishOnce();
                    r->deleteLater();
                });
            });
        } else {
            finishOnce();
        }
        vtReply->deleteLater();
    });

    // Google Safe Browsing
    QNetworkRequest gsbReq;
    QUrlQuery query;
    query.addQueryItem("key", GSB_API_KEY);
    QUrl gsbUrl("https://safebrowsing.googleapis.com/v4/threatMatches:find?" + query.toString());
    gsbReq.setUrl(gsbUrl);
    gsbReq.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    QJsonObject threatEntry{{"url", url}};
    QJsonArray entries;
    entries.append(threatEntry);
    QJsonObject threatInfo;
    threatInfo["threatTypes"] = QJsonArray() << "MALWARE" << "SOCIAL_ENGINEERING";
    threatInfo["platformTypes"] = QJsonArray() << "ANY_PLATFORM";
    threatInfo["threatEntryTypes"] = QJsonArray() << "URL";
    threatInfo["threatEntries"] = entries;

    QJsonObject body;
    body["client"] = QJsonObject{{"clientId", "CyberLens"}, {"clientVersion", "1.0"}};
    body["threatInfo"] = threatInfo;

    QNetworkReply *gsbReply = networkManager->post(gsbReq, QJsonDocument(body).toJson());
    connect(gsbReply, &QNetworkReply::finished, this, [this, gsbReply, riskScorePtr, finishOnce]() {
        if (gsbReply->error() == QNetworkReply::NoError) {
            QJsonDocument doc = QJsonDocument::fromJson(gsbReply->readAll());
            if (!doc.object()["matches"].toArray().isEmpty()) {
                *riskScorePtr = qMax(*riskScorePtr, 98);
            }
        }
        finishOnce();
        gsbReply->deleteLater();
    });

    QTimer::singleShot(25000, this, [finishOnce]() {
        finishOnce();
    });
}

void MainWindow::finishUrlAnalysis(int score, const QString &extraInfo)
{
    QString message;
    if (score > 70)
        message = "🔴 This link is likely malicious. Avoid opening it." + extraInfo;
    else if (score > 40)
        message = "🟡 This link shows suspicious behavior." + extraInfo;
    else
        message = "🟢 This link appears safe to use." + extraInfo;

    QString resultText = "Risk Score: " + QString::number(score) + "/100\t" + message;
    ui->urlRiskScore->setText(resultText);
    ui->urlRiskScore->setStyleSheet(
        score > 70 ? "color:red; font-weight:bold;" :
            score > 40 ? "color:orange; font-weight:bold;" :
            "color:#4ade80; font-weight:bold;"
        );
    historyList.append({"URL", lastScannedUrl, resultText});
}

void MainWindow::performFileAnalysis(const QString &filePath, const QString &hash)
{
    QStringList riskyExt = {".exe", ".scr", ".bat", ".vbs", ".js", ".cmd", ".msi", ".jar"};
    bool isRiskyExtension = false;
    for (const QString &ext : riskyExt) {
        if (filePath.endsWith(ext, Qt::CaseInsensitive)) {
            isRiskyExtension = true;
            break;
        }
    }

    if (isOnline) {
        ui->verdictLabel->setText("🔄 Consulting VirusTotal Database...");
        ui->verdictLabel->setStyleSheet("color:#facc15; font-weight:bold;");
        QNetworkRequest req(QUrl("https://www.virustotal.com/api/v3/files/" + hash));
        req.setRawHeader("x-apikey", VT_API_KEY);
        QNetworkReply *reply = networkManager->get(req);
        connect(reply, &QNetworkReply::finished, this, [this, reply, filePath, isRiskyExtension]() {
            QString resultText;
            int totalDetections = 0;
            bool foundInDb = false;
            if (reply->error() == QNetworkReply::NoError) {
                QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
                if (doc.object().contains("data")) {
                    foundInDb = true;
                    QJsonObject stats = doc.object()["data"].toObject()["attributes"].toObject()["last_analysis_stats"].toObject();
                    int malicious = stats["malicious"].toInt();
                    int suspicious = stats["suspicious"].toInt();
                    totalDetections = malicious + suspicious;
                }
            }

            if (!foundInDb) {
                if (isRiskyExtension) {
                    resultText = "Detections: Unknown\t🟠 Unknown file with risky extension. Exercise caution.";
                    ui->verdictLabel->setStyleSheet("color:#f97316; font-weight:bold;");
                } else {
                    resultText = "Detections: Unknown\t🔵 New or unknown file. No threats reported yet.";
                    ui->verdictLabel->setStyleSheet("color:#3b82f6; font-weight:bold;");
                }
            } else {
                if (totalDetections > 0) {
                    resultText = "Detections: " + QString::number(totalDetections) + "/100\t🔴 Malicious activity detected.";
                    ui->verdictLabel->setStyleSheet("color:#dc2626; font-weight:bold;");
                } else {
                    resultText = "Detections: 0/100\t🟢 File is known and appears clean.";
                    ui->verdictLabel->setStyleSheet("color:#16a34a; font-weight:bold;");
                }
            }
            ui->verdictLabel->setText(resultText);
            historyList.append({"File", filePath, resultText});
            reply->deleteLater();
        });
    } else {
        QString statusText = isRiskyExtension ? "🔴 High Risk: Executable file (Offline Check)." : "🟢 Low Risk: Standard data file (Offline Check).";
        QString resultText = "Score: " + QString(isRiskyExtension ? "85" : "0") + "/100 — " + statusText;
        ui->verdictLabel->setText(resultText);
        ui->verdictLabel->setStyleSheet(isRiskyExtension ? "color:#dc2626; font-weight:bold;" : "color:#16a34a; font-weight:bold;");
        historyList.append({"File", filePath, resultText});
    }
}

void MainWindow::on_btnAnalyzeUrl_clicked()
{
    QString cleanUrl = sanitizeUrl(ui->urlInput->text());

    if (cleanUrl.isEmpty()) {
        ui->urlRiskScore->setText("Invalid or unsafe URL format!");
        ui->urlRiskScore->setStyleSheet("color:red; font-weight:bold;");
        return;
    }

    ui->urlInput->setText(cleanUrl);

    if (isOnline) {
        analyzeUrlOnline(cleanUrl);
    } else {
        // OFFLINE: OpenPhish FIRST, then heuristics
        bool openPhishMatch = isInOpenPhish(cleanUrl);

        int score = openPhishMatch ? 99 : offlineUrlScore(cleanUrl);
        QString extra = openPhishMatch ? " (Detected by OpenPhish blacklist)" : "";

        finishUrlAnalysis(score, extra);
    }
}

void MainWindow::on_btnBrowse_clicked()
{
    QString filePath = QFileDialog::getOpenFileName(this, "Select File to Scan");
    if (filePath.isEmpty()) return;
    QString hash = computeSHA256(filePath);
    if (hash.isEmpty()) {
        QMessageBox::warning(this, "Error", "Cannot read file.");
        return;
    }
    lastScannedHash = hash;
    lastScannedUrl = "";
    ui->hashLabel->setText("SHA-256: " + hash.left(20) + "...");
    performFileAnalysis(filePath, hash);
}

void MainWindow::on_historyBtn_clicked()
{
    if (historyList.isEmpty()) {
        QMessageBox::information(this, "Scan History", "No scans performed yet.");
        return;
    }
    QString text = "<h2 style='color:#60a5fa; text-align:center;'>CyberLens Scan History</h2><hr>";
    for (int i = 0; i < historyList.size(); ++i) {
        const HistoryItem &item = historyList.at(i);
        text += QString("<p><b>%1.</b> <b>Type:</b> %2<br>"
                        "<b>Target:</b> %3<br>"
                        "<b>Result:</b> %4</p><hr>")
                    .arg(i + 1)
                    .arg(item.type)
                    .arg(item.item.toHtmlEscaped())
                    .arg(item.result.toHtmlEscaped());
    }
    QMessageBox msgBox(this);
    msgBox.setWindowTitle("Scan History");
    msgBox.setTextFormat(Qt::RichText);
    msgBox.setText(text);
    msgBox.setStyleSheet("QMessageBox { background-color: #1e293b; color: white; } QLabel { color: white; }");
    msgBox.exec();
}

void MainWindow::on_reportBtn_clicked()
{
    if (historyList.isEmpty()) {
        QMessageBox::information(this, "Report", "No scans to include in report.");
        return;
    }
    QString report = "CyberLens Threat Analysis Report\n";
    report += "Generated: " + QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss") + "\n";
    report += "==================================================\n\n";
    for (int i = 0; i < historyList.size(); ++i) {
        const HistoryItem &item = historyList.at(i);
        report += QString("%1. Type: %2\n Target: %3\n Result: %4\n\n")
                      .arg(i + 1)
                      .arg(item.type)
                      .arg(item.item)
                      .arg(item.result);
    }
    report += "==================================================\n";
    report += "Total Scans: " + QString::number(historyList.size()) + "\n";

    QString fileName = QFileDialog::getSaveFileName(this, "Save Report",
                                                    QStandardPaths::writableLocation(QStandardPaths::DesktopLocation) + "/CyberLens_Report.txt",
                                                    "Text Files (*.txt)");
    if (fileName.isEmpty()) return;

    QFile file(fileName);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&file);
        out << report;
        file.close();
        QMessageBox::information(this, "Success", "Report saved successfully!");
    }
}

void MainWindow::loadOpenPhishFeed()
{
    if (!isOnline) return;
    QNetworkRequest request(QUrl("https://openphish.com/feed.txt"));
    QNetworkReply *reply = networkManager->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        if (reply->error() == QNetworkReply::NoError) {
            parseOpenPhishData(reply->readAll());
            openPhishLoaded = true;
            lastOpenPhishUpdate = QDateTime::currentDateTime();
        }
        reply->deleteLater();
    });
}

void MainWindow::parseOpenPhishData(const QByteArray &data)
{
    openPhishUrls.clear();
    openPhishDomains.clear();
    QTextStream stream(data);
    while (!stream.atEnd()) {
        QString line = stream.readLine().trimmed();
        if (line.isEmpty() || !line.startsWith("http")) continue;
        openPhishUrls.insert(line);
        QUrl qurl(line);
        QString host = qurl.host();
        if (host.startsWith("www.")) host = host.mid(4);
        openPhishDomains.insert(host);
    }
}

bool MainWindow::isInOpenPhish(const QString &url)
{
    if (!openPhishLoaded) return false;
    if (openPhishUrls.contains(url)) return true;
    QUrl qurl(url);
    QString host = qurl.host();
    if (host.startsWith("www.")) host = host.mid(4);
    return openPhishDomains.contains(host);
}
