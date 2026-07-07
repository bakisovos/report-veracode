# SQL Injection (CWE-89)

**Kategori:** SQL Injection · **CWE:** 89 · **Effort to Fix:** 3 · **Exploitability:** Very Likely · **Severity:** High

## Açıklama
Uygulama, SQL sorgusunu untrusted input'u string olarak birleştirerek oluşturuyor. Saldırgan sorgu mantığını değiştirip yetkisiz veri okuyabilir/değiştirebilir, kimlik doğrulamayı atlayabilir veya komut çalıştırabilir.

## Çözüm Önerisi
**Parameterized query / prepared statement** kullanın; kullanıcı girdisini asla SQL string'ine doğrudan eklemeyin. ORM kullanılıyorsa parametrik API'lerde kalın. Ek katman olarak pozitif input doğrulaması ve en az ayrıcalıklı DB hesabı uygulayın.

---

## TASK-SQLI-01 — Dinamik sorgu birleştirme · Data katmanı
- **Konum:** `DigitalPlanet.NetInvoice.dll` → data access metotlarında string concatenation ile kurulan SQL
- **Etkilenen:** Tüm portaller (ortak DLL)
- **Aksiyon:** İlgili metotları `SqlParameter` tabanlı parametrik sorgulara çevir

## TASK-SQLI-02 — Rapor sorguları · `Task.BABSReport`
- **Konum:** `DigitalPlanet.NetInvoice.Task.dll` → `Task.BABSReport` içindeki rapor sorguları
- **Etkilenen:** NetDespatch, Netbook, NetInvoiceWindowsServices

> **Not:** SQLi bulguları High severity ve "Very Likely" exploitability taşıdığından, remediation önceliğinde CWE-89 kalemleri en üstte değerlendirilmelidir.
