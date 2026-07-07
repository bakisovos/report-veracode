# Credentials Management (CWE-798, CWE-259)

**Kategori:** Credentials Management · **Effort to Fix:** 4 (yeniden tasarım, ~5 gün) · **Exploitability:** Likely

## Açıklama
Uygulama kodunda **hard-coded credential / password** bulunuyor. Kod prod'a çıktıktan sonra parola yamalanmadan değiştirilemez; kaynak koda erişen herkes görebilir. Bir örnek sızarsa tüm kurulumlar risk altındadır.

## Çözüm Önerisi
Parolaları/anahtarları kod dışında (out-of-band) saklayın — configuration/properties dosyaları, secret manager vb. Hard-coded kullanıcı adı/parola/hash sabitlerinden kaçının. Alternatif konumlardaki credential'ları koruma best-practice'lerini uygulayın.

---

## TASK-CREDS-01 — Use of Hard-coded Credentials (CWE-798) · `LoginByAnyAccountHelper.!cctor`
- **Konum:** `DigitalPlanet.NetInvoice.Web.dll` → `NetInvoice.Web.LoginByAnyAccountHelper.!cctor()` (%50 ve %69)
- **Etkilenen uygulamalar:**
  - IST_Dtp-NetSeVoucherWebPortal (1052-17, 1053-17)
  - IST_Dtp-NetDespatchWebPortal (1589-35, 1590-35)
  - IST_Dtp-NetbookWebPortal (1249-38, 1250-38)

## TASK-CREDS-02 — Use of Hard-coded Password (CWE-259) · `NetInvoice.Web...BaBsResult.Decrypt`
- **Konum:** `DigitalPlanet.NetInvoice.Web.dll` → `NetInvoice.Web.NetInvoice.BaBsResult.Decrypt(string)` (%23)
- **Etkilenen uygulamalar:**
  - IST_Dtp-NetSeVoucherWebPortal (1026-18)
  - IST_Dtp-NetDespatchWebPortal (113-37)
  - IST_Dtp-NetbookWebPortal (1453-40)

## TASK-CREDS-03 — Use of Hard-coded Password (CWE-259) · `BaBsResult.!cctor`
- **Konum:** `DigitalPlanet.NetInvoice.Web.dll` → `NetInvoice.Web.NetInvoice.BaBsResult.!cctor()` (%16)
- **Etkilenen uygulamalar:**
  - IST_Dtp-NetSeVoucherWebPortal (1028-18)
  - IST_Dtp-NetDespatchWebPortal (2078-37)
  - IST_Dtp-NetbookWebPortal (1906-40)

## TASK-CREDS-04 — Use of Hard-coded Password (CWE-259) · `BABSReportTemplate` (Task DLL)
- **Konum:** `DigitalPlanet.NetInvoice.Task.dll` → `Task.BABSReport.BABSReportTemplate` içinde `Encrypt` (%24) ve `!cctor` (%16)
- **Etkilenen uygulamalar:**
  - IST_Dtp-NetDespatchWebPortal (1763-23 `Encrypt`; 115-23 `!cctor`)
  - IST_Dtp-NetbookWebPortal (1329-25 `Encrypt`; 1256-25 `!cctor`)

> **Not:** Bu 4 task `DigitalPlanet.NetInvoice.Web.dll` ve `DigitalPlanet.NetInvoice.Task.dll` ortak modüllerinde. Düzeltmeler NetSeVoucher, NetDespatch ve Netbook portallarını birlikte kapatır.
