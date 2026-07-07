# Code Quality (CWE-459, CWE-476, CWE-404 vb.)

**Kategori:** Code Quality · **Effort to Fix:** 1–2 · **Exploitability:** Unlikely · **Severity:** Low/Informational

## Açıklama
Doğrudan sömürülebilir olmasa da güvenilirlik ve güvenliği zayıflatan kod kalitesi bulguları: eksik kaynak temizliği (incomplete cleanup), olası null pointer dereference, kapatılmayan kaynaklar (unreleased resource) vb.

## Çözüm Önerisi
Kaynakları `using` / `try-finally` ile deterministik biçimde serbest bırakın. Null olabilecek referansları dereference öncesi kontrol edin. Exception path'lerinde de temizliğin çalıştığını doğrulayın.

---

## TASK-CQ-01 (CWE-459) — Incomplete Cleanup
- **Konum:** `DigitalPlanet.NetInvoice.dll` / `*.Task.dll` → exception durumunda temizlenmeyen geçici kaynaklar
- **Etkilenen:** Ortak modülleri kullanan portaller

## TASK-CQ-02 (CWE-476) — Null Pointer Dereference
- **Konum:** Çeşitli handler ve business metotları
- **Etkilenen:** NetReceipt, NetDespatch, Netbook (ortak modül)

## TASK-CQ-03 (CWE-404) — Improper Resource Shutdown / Release
- **Konum:** Dosya/stream açıp kapatmayan yollar (`using` eksik)
- **Etkilenen:** Web handler'ları (ortak `DigitalPlanet.NetInvoice.Web.dll`)

> **Not:** Bu kalemler Low/Informational; SQLi, Crypto ve Directory Traversal düzeltmelerinden sonra ele alınabilir.
