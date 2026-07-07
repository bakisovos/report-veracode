# Directory Traversal (CWE-22)

**Kategori:** Directory Traversal · **CWE:** 22 · **Effort to Fix:** 3 (~5 gün) · **Exploitability:** Likely

## Açıklama
Uygulama, dosya sistemi yolunu oluştururken untrusted input'u yeterince temizlemeden kullanıyor. Saldırgan `../` gibi dizi geçişi ifadeleriyle amaçlanan dizinin dışına çıkıp keyfi dosyaları okuyabilir/yazabilir.

## Çözüm Önerisi
Dosya adı/yolu için untrusted input'u doğrudan kullanmayın. Zorunluysa: (1) pozitif whitelist doğrulaması yapın, (2) `../`, mutlak yol, null byte gibi karakterleri reddedin, (3) canonical path'i çözüp izin verilen kök dizinin altında kaldığını doğrulayın (`Path.GetFullPath` + `StartsWith(rootDir)`).

---

## TASK-DIRTRAV-01 — `Handler.Resource.ProcessRequest` (%88)
- **Konum:** `DigitalPlanet.NetInvoice.Web.dll` → `NetInvoice.Web.Handler.Resource.ProcessRequest(HttpContext)`
- **Etkilenen:** NetSeVoucher (1063-10), NetDespatch (124-27), Netbook (1451-31)

## TASK-DIRTRAV-02 — `Template.InvoiceExport.ProcessRequest` (%80)
- **Konum:** `DigitalPlanet.NetInvoice.Web.dll` → `NetInvoice.Web.Template.InvoiceExport.ProcessRequest(HttpContext)`
- **Etkilenen:** NetSeVoucher (1064-21), NetReceipt (1156-20), NetDespatch (125-28), Netbook (1270-32), NetInvoiceWebPortal (`invoiceexport.ashx.cs` 202), NetInvoiceWebServices (aynı)

## TASK-DIRTRAV-03 — `Handlers.DownloadEarchiveReport.ProcessRequest` (%80)
- **Konum:** `DigitalPlanet.NetInvoice.Web.dll` → `Handlers.DownloadEarchiveReport.ProcessRequest`
- **Etkilenen:** NetReceipt (4214-29), Netbook (1443-39), NetInvoiceWebPortal (`downloadearchivereport.ashx.cs` 65), NetInvoiceWebServices (aynı)

## TASK-DIRTRAV-04 — Handler dosyaları (`.ashx.cs`) — modül-özel
- `sevoucherexport.ashx.cs` 219 → NetSeVoucher
- `receiptexport.ashx.cs` 185 → NetReceipt
- `getnetbookhandler.ashx.cs` 280 → Netbook

## TASK-DIRTRAV-05 — `SovosMW.EArchive` dosya okuma — Middleware özel
- **Konum:** `SovosMW.EArchive.Core.dll` → dosya path handler
- **Etkilenen:** IST_DTP_EARC_Middleware — **grace period kontrolü gerekli**
