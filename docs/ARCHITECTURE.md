# Architecture (Java / Spring Boot edition)
| Package | Contents | Notes |
|---|---|---|
| `com.qrshield.core` | `UrlValidator`, `RiskScorer`, `Analyzer`, `Privacy`, `ThreatIntelProvider`, `SafeBrowsingProvider`, records | Plain Java, **no Spring**. The engine to explain in a viva. |
| `com.qrshield.qr` | `QrReader` | ImageIO validation (format, pixel limit) + ZXing decoding. |
| `com.qrshield.data` | `ScanRepository`, `ScanView` | JdbcTemplate + SQLite. All SQL parameterized. |
| `com.qrshield.web` | Controllers, `ScanService`, `SecurityConfig`, `AppConfig`, `QrShieldProperties` | HTTP only; one shared `ScanService` for URL and QR scans. |
| `resources/templates` | Thymeleaf pages | `th:text` auto-escapes all user data. |

Flow (URL): `POST /scan` → CSRF check → `UrlValidator` → 14 rules in `RiskScorer` → optional provider → `Privacy.redactUrl` → INSERT → redirect `/result/{id}`.
Flow (QR): `POST /qr-scanner` → extension + MIME check → random temp file → `QrReader.decode` → temp file deleted → each code classified → URL codes use the same flow.
Spring Security is used only for CSRF and headers (CSP, nosniff, frame deny, no-referrer); there is no login.
Differences from the Python version: WebP uploads are not supported (Java ImageIO has no WebP reader); default port 8080; QR decoding uses ZXing instead of OpenCV.
