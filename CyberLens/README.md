# 🔍 CyberLens

CyberLens is a modern desktop cybersecurity application designed to scan URLs and files
for potential security threats. The project focuses on detecting malicious URLs
(phishing, malware domains) and identifying suspicious files using hash-based analysis.

CyberLens is built primarily for educational and personal cybersecurity use and demonstrates
practical implementation of secure coding, networking, and malware detection concepts.

--

## ✨ Features

- Intuitive graphical user interface built with Qt Widgets  
- URL analysis and threat detection  
- File scanning using cryptographic hash computation  
- Scan history tracking and management  
- Modular architecture for easy feature extension  
- Lightweight and fast desktop application  

---
## 📸 Screenshots

**Main Application Window**  
![Main Application Window](screenshorts/mainwindow.png)

**File Scanning Example**  
![File Scanning Example](screenshorts/filescaning.png)

**URL Scanning Example**  
![URL Scanning Example](screenshorts/urlscaning.png)

**Scan History View**  
![Scan History View](screenshorts/scannhistory.png)

**Report Generation / Results**  
![Report Generation / Results](screenshorts/reportsgeneratings.png)

**Network Checker Interface**  
![Network Checker Interface](screenshorts/networkchecker.png)
## 🛠️ Tech Stack

- **Programming Language:** C++ (C++17 or later)  
- **Framework:** Qt 6 (Widgets & Network modules)  
- **Build System:** CMake  
- **Platform:** Cross-platform (Windows / Linux)  

---

## 📁 Project Structure

```text
CyberLens/
├── CMakeLists.txt          # Build configuration (CMake)
├── README.md               # This file
├── main.cpp                # Application entry point
├── mainwindow.h
├── mainwindow.cpp
├── mainwindow.ui           # Qt Designer UI file
├── filescanner.h
├── filescanner.cpp
├── networkchecker.h
├── networkchecker.cpp
├── urlanalyzer.h           # Note: was urianalyzer in earlier messages
├── urlanalyzer.cpp
├── reportgenerator.h
├── reportgenerator.cpp
├── historymanager.h
├── historymanager.cpp
└── screenshots/            # Folder for images shown in README
    └── "C:\Users\user\Pictures\Screenshots\Screenshot 2026-01-20 121806.png"

🎯 Learning Outcomes

Practical experience with cybersecurity concepts

Secure coding practices in C++

URL threat analysis techniques

File hashing and integrity checking

Desktop application development using Qt

🚀 Future Enhancements

Integration with online threat intelligence APIs

PDF/CSV report export

Real-time URL monitoring

Improved malware detection logic

👤 Author

Muhammad Jamshed
Cybersecurity Student
GitHub:https://github.com/JAMSHEDKHOSA57



