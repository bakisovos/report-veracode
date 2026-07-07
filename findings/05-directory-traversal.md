# Directory Traversal (CWE-73) — External Control of File Name or Path

**Kategori:** Directory Traversal · **CWE:** 73 · **Benzersiz Task:** 28 · **Effort to Fix:** 3 (~5 gün) · **Exploitability:** Likely

## Açıklama
Uygulama, dosya sistemi yolunu/adını oluştururken untrusted input'u yeterince doğrulamadan kullanıyor (external control of file name or path). Saldırgan `../` gibi dizi geçişi ifadeleri veya mutlak yol vererek amaçlanan dizinin dışına çıkıp keyfi dosyaları okuyabilir/yazabilir/silebilir.

## Çözüm Önerisi
Dosya adı/yolu için untrusted input'u doğrudan kullanmayın. Zorunluysa: (1) pozitif whitelist doğrulaması yapın, (2) `../`, mutlak yol, null byte gibi ifadeleri reddedin, (3) canonical path'i çözüp (`Path.GetFullPath`) izin verilen kök dizinin altında kaldığını doğrulayın (`StartsWith(rootDir)`), (4) mümkünse dosyalara doğrudan kullanıcı girdisi yerine indeks/ID ile erişin.

> **Not:** Bulguların büyük çoğunluğu ortak `DigitalLibrary.Web.dll` ve `DigitalPlanet.NetInvoice.Web.dll` modüllerinde. Tek düzeltme birden fazla portalı kapatır.

---

## TASK-DIRTRAV-01 — `DigitalLibrary.Web...WebSettings.Save` (en yüksek etki, 12 instance)
- **Konum:** `DigitalLibrary.Web.dll` → `DigitalLibrary.Web.Configuration.WebSettings.Save(...)`
- **Etkilenen uygulamalar:** DigitalLibrary (kaynak), NetSeVoucher, NetReceipt, NetDespatch, NetInvoiceWindowsServices, NetInvoiceWebPortal, NetInvoiceWebServices, Netbook
- **Aksiyon:** Ayar dosyası yolunu whitelist + canonical-path kontrolüyle sabitleyin; kullanıcı girdisini path'e eklemeyin

## TASK-DIRTRAV-02 — `Handler.Resource.ProcessRequest` (%88)
- **Konum:** `DigitalPlanet.NetInvoice.Web.dll` → `NetInvoice.Web.Handler.Resource.ProcessRequest(HttpContext)`
- **Etkilenen:** NetSeVoucher (1063-10), NetDespatch (124-27), Netbook (1451-31)

## TASK-DIRTRAV-03 — `Template.InvoiceExport.ProcessRequest` (%80)
- **Konum:** `DigitalPlanet.NetInvoice.Web.dll` → `NetInvoice.Web.Template.InvoiceExport.ProcessRequest(HttpContext)`
- **Etkilenen:** NetSeVoucher (1064-21), NetReceipt (1156-20), NetDespatch (125-28), Netbook (1270-32), NetInvoiceWebPortal (`invoiceexport.ashx.cs` 202), NetInvoiceWebServices (aynı)

## TASK-DIRTRAV-04 — `Handlers.DownloadEarchiveReport.ProcessRequest` (%80)
- **Konum:** `DigitalPlanet.NetInvoice.Web.dll` → `Handlers.DownloadEarchiveReport.ProcessRequest`
- **Etkilenen:** NetReceipt (4214-29), Netbook (1443-39), NetInvoiceWebPortal (`downloadearchivereport.ashx.cs` 65), NetInvoiceWebServices (aynı)

## TASK-DIRTRAV-05 — `Handlers.DownloadEArchiveIcmalReport.ProcessRequest`
- **Konum:** `DigitalPlanet.NetInvoice.Web.dll` → `Handlers.DownloadEArchiveIcmalReport.ProcessRequest`
- **Etkilenen:** NetSeVoucher, NetDespatch, Netbook

## TASK-DIRTRAV-06 — Handler dosyaları (`.ashx.cs`) — modül-özel
- `sevoucherexport.ashx.cs` 219 → NetSeVoucher
- `receiptexport.ashx.cs` 185 → NetReceipt
- `getnetbookhandler.ashx.cs` 280 → Netbook
- `downloadreceiptreport.ashx.cs` 69 / `downloadreceiptreporthandler.ashx.cs` 72 → NetReceipt

## TASK-DIRTRAV-07 — `SovosMW.EArchive` dosya okuma — Middleware özel
- **Konum:** `SovosMW.EArchive.Core.dll` → dosya path handler
- **Etkilenen:** IST_DTP_EARC_Middleware — **grace period kontrolü gerekli**

> **Toplam:** README envanterinde bu kategori 28 instance/task ile en yüksek adetli kalemdir; yukarıdaki gruplar dedup edilmiş hâldir. Öncelik: ortak modül düzeltmeleri (TASK-DIRTRAV-01/02/03/04).
