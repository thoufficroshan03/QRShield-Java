# QRShield (Java / Spring Boot edition)
**A Web-Based Pre-Click Link and QR Code Risk Analyzer with Explainable Threat Indicators and Scan History**

Same product as the Python/Flask version, rebuilt in Java: Spring Boot 3, Thymeleaf, SQLite, ZXing, Bootstrap 5 and Chart.js (bundled locally), JUnit 5.

## Features
URL analyzer (15 explainable rules, including brand-clone/typo-squatting detection, 0–100 score, configurable thresholds) · QR image scanner (multi-code aware) · scan history with level/date filters, pagination, detail pages and confirmed clear · dashboard with Chart.js · optional Google Safe Browsing (off by default) · CSRF, CSP and security headers · submitted URLs are **never fetched**.

## Prerequisites (Windows)
1. **JDK 17 or newer** (e.g. Eclipse Temurin 21). Check: `java -version`
2. **Apache Maven 3.9+**. Check: `mvn -version` (install with `winget install Apache.Maven` or from maven.apache.org, then reopen PowerShell)
3. VS Code with *Extension Pack for Java* (optional but recommended)

## Run (PowerShell, from the folder that contains `pom.xml`)
```powershell
mvn test              # runs all tests (needs internet the first time to download dependencies)
mvn spring-boot:run   # starts the app
```
Open http://127.0.0.1:8080. Stop with Ctrl+C. The SQLite file is created at `instance\qrshield.db`; to reset it, stop the app and delete that file.
Build a jar: `mvn package` then `java -jar target\qrshield-1.0.0.jar`.

## Configuration
Edit `src/main/resources/application.properties` (thresholds, page size, upload pixel limit). Secrets only via environment variables:
```powershell
$env:TI_PROVIDER = "safebrowsing"
$env:SAFE_BROWSING_API_KEY = "your-key"
mvn spring-boot:run
```
With the provider enabled, the URL **string** is sent to Google. Without a key the app works fully offline. A provider "no match" is never described as proof of safety.

## Score meaning
0–24 Low, 25–59 Medium, 60–100 High. Provisional heuristic thresholds, not validated against a dataset. A low score never guarantees safety; HTTPS does not prove legitimacy.

## Security and privacy
No live fetching (no SSRF surface); server-side validation; Thymeleaf auto-escaping; parameterized SQL; 2 MB / 12-megapixel upload limits; extension + MIME + real image decode; random temp filename deleted after use; CSRF tokens; CSP. Stored URLs have credentials/fragment removed, query values replaced with `[redacted]`, token-like path segments masked (reduces, but does not guarantee removal of, sensitive data). **No login**: single-user local app; add authentication and HTTPS before any public deployment.

## Limitations
Clone detection uses a small built-in brand list and character similarity, so it can produce false positives/negatives; no WebP uploads; ZXing may miss damaged QR codes; no authentication.

## Folder structure
```
src/main/java/com/qrshield/{core,qr,data,web}   src/main/resources/{templates,static,schema.sql,application.properties}
src/test/java/com/qrshield/{core,qr,web}        docs/ARCHITECTURE.md   pom.xml   instance/
```

## GitHub
```powershell
git init
git add .
git commit -m "QRShield Java edition"
git branch -M main
git remote add origin https://github.com/<your-username>/QRShield-Java.git
git push -u origin main
```

## Troubleshooting
`mvn` not recognised → install Maven and reopen PowerShell. · Wrong Java version → set JAVA_HOME to JDK 17+. · Port 8080 busy → set `server.port` in application.properties. · Form shows "Request could not be completed" after a long idle → reload the page (CSRF session expired).
