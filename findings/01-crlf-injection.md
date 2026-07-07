# CRLF Injection (CWE-117) — Improper Output Neutralization for Logs

**Kategori:** CRLF Injection · **CWE:** 117 · **Effort to Fix:** 2 (6-50 satır, ~1 gün) · **Exploitability:** Likely

## Açıklama
Untrusted veri log dosyasına doğru şekilde nötrlenmeden yazılıyor. Saldırgan log'a sahte kayıt enjekte edebilir (log forging), izlerini gizleyebilir veya log görüntüleyicide XSS tetikleyebilir.

## Çözüm Önerisi
Log'a yazılan tüm untrusted veriyi merkezi bir doğrulama/temizleme rutininden geçirin. OWASP ESAPI Logger gibi CR/LF'i otomatik temizleyen güvenli bir loglama mekanizması kullanın. Non-alphanumeric karakterleri HTML-entity encode edin.

---

## TASK-CRLF-01 — `DigitalLibrary.Logging.FileLogger.Write` (log forging)
- **Konum:** `filelogger.cs` (satır 36, 39, 42, 45) → `DigitalLibrary.dll` içindeki `DigitalLibrary.Logging.FileLogger.Write(LogType, ExceptionBase, string, int, ...)`
- **Not:** Aynı 4 `Write` overload'ı tüm raporlarda tekrar ediyor. `DigitalLibrary.dll` ortak modül olduğu için **tek düzeltme = tüm uygulamalar**.
- **Etkilenen uygulamalar (raporlar):**
  - IST_Dtp_DigitalLibrary (`filelogger.cs` 36/39/42/45 — kaynak)
  - IST_Dtp-NetSeVoucherWebPortal (309/308/307/306)
  - IST_Dtp-NetReceiptWebPortal (104/103/102/101)
  - IST_Dtp-NetDespatchWebPortal (833/832/831/830)
  - IST_Dtp-NetInvoiceWindowsServices (17697/17695/17694/17690)
  - IST_Dtp-NetInvoiceWebPortal (1430/1429/1428/1423)
  - IST_Dtp-NetInvoiceWebServices (1893/1892/1891/1890)
  - IST_Dtp-NetbookWebPortal (83/82/81/80)

## TASK-CRLF-02 — `DigitalPlanet.NetInvoice.StaticLoggerWriter.Start`
- **Konum:** `staticlogger.cs` 45 → `DigitalPlanet.NetInvoice.dll` içinde `StaticLoggerWriter.Start()`
- **Etkilenen uygulamalar:**
  - IST_Dtp-NetSeVoucherWebPortal (1059-9)
  - IST_Dtp-NetReceiptWebPortal (1143-16)
  - IST_Dtp-NetDespatchWebPortal (1767-20)
  - IST_Dtp-NetInvoiceWebPortal (1463-23)
  - IST_Dtp-NetInvoiceWebServices (2112-25)
  - IST_Dtp-NetbookWebPortal (1447-21)

## TASK-CRLF-03 — `Core.dll` → `MyEventLog` (HotFolderLite)
- **Konum:** `myeventlog.cs` 23 → `Core.dll` içinde `MyEventLog` (service/log)
- **Etkilenen uygulamalar:**
  - IST_Dtp-NetInvoiceWindowsServices (17688-7)
