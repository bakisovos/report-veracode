# Cross-Site Scripting / XSS (CWE-80) — Basic XSS

**Kategori:** Cross-Site Scripting (XSS) · **CWE:** 80 · **Effort to Fix:** 3 (51-500 satır, ~5 gün)

## Açıklama
Uygulama HTTP yanıtını untrusted input ile dolduruyor; saldırgan kurbanın tarayıcısında çalışacak zararlı içerik (ör. JavaScript) gömebilir. Çerez çalma, içerik değiştirme, hassas bilgi ifşası mümkündür.

## Çözüm Önerisi
Tüm untrusted veriyi HTTP yanıtı oluşturmadan önce **contextual escaping** ile temizleyin (HTML body → HTML-entity, attribute → attribute escaping vb.). Framework'ün otomatik XSS escaping'ini kapatmayın. Microsoft AntiXSS / OWASP Java Encoder kullanın. Ek olarak pozitif (whitelist) input doğrulaması yapın.

> **Not:** `.web.dll` handler'larının çoğu ortak `DigitalPlanet.NetInvoice.Web.dll` modülünde. Aynı sınıf+metot birden fazla portalda tekrar ediyor → aşağıda birleştirildi.

---

## TASK-XSS-01 — `Handler.Resource.ProcessRequest` (%95)
- **Konum:** `DigitalPlanet.NetInvoice.Web.dll` → `NetInvoice.Web.Handler.Resource.ProcessRequest(HttpContext)`
- **Etkilenen:** NetSeVoucher (1062-10), NetDespatch (112-27), Netbook (1452-31)

## TASK-XSS-02 — `Layouts.GetError.Page_Load` (%91)
- **Konum:** `DigitalPlanet.NetInvoice.Web.dll` → `NetInvoice.Web.Layouts.GetError.Page_Load`
- **Etkilenen:** NetSeVoucher (1032-15), NetDespatch (117-33), Netbook (1442-36)

## TASK-XSS-03 — `Template.InvoiceExport.ProcessRequest` (%95/96)
- **Konum:** `DigitalPlanet.NetInvoice.Web.dll` → `NetInvoice.Web.Template.InvoiceExport.ProcessRequest(HttpContext)`
- **Etkilenen:** NetSeVoucher (1061-21), NetReceipt (1155-20), NetDespatch (118-28 / 119-29), Netbook (1267-32 / 1268-33), NetInvoiceWebPortal (1460-17 `invoiceexport.ashx.cs` 202), NetInvoiceWebServices (135-18 `invoiceexport.ashx.cs` 202)

## TASK-XSS-04 — `Handlers.DownloadEarchiveReport.ProcessRequest` (%95/96)
- **Konum:** `DigitalPlanet.NetInvoice.Web.dll` → `NetInvoice.Web.Handlers.DownloadEarchiveReport.ProcessRequest`
- **Etkilenen:** NetReceipt (4212-29), NetDespatch (?), Netbook (1441-39), NetInvoiceWebPortal (`downloadearchivereport.ashx.cs` 65 = 369-6), NetInvoiceWebServices (137-7 `downloadearchivereport.ashx.cs` 65)

## TASK-XSS-05 — `Handlers.DownloadEArchiveIcmalReport.ProcessRequest` (%96)
- **Konum:** `DigitalPlanet.NetInvoice.Web.dll` → `Handlers.DownloadEArchiveIcmalReport.ProcessRequest`
- **Etkilenen:** NetSeVoucher (Flaws in Common Modules), NetDespatch (116-36), Netbook (1456-46)

## TASK-XSS-06 — `Handlers.GetErpData.ProcessRequest` (%52)
- **Konum:** `DigitalPlanet.NetInvoice.Web.dll` → `Handlers.GetErpData.ProcessRequest`
- **Etkilenen:** NetDespatch (120-30), Netbook (1269-34)

## TASK-XSS-07 — `NetInvoice.IncomingErpDataView.btnDownload_Click` (%83/87)
- **Konum:** `DigitalPlanet.NetInvoice.Web.dll` → `NetInvoice.IncomingErpDataView`
- **Etkilenen:** NetReceipt (1151-27), NetDespatch (422-39), Netbook (1440-44), NetInvoiceWebPortal (`incomingerpdataview.aspx.cs` 34), NetInvoiceWebServices (122-13 aynı satır)

## TASK-XSS-08 — `NetGateWayReports.LargeFileHandler.ProcessRequest` (%87)
- **Konum:** `DigitalPlanet.NetInvoice.Web.dll` → `NetGateWayReports.LargeFileHandler.ProcessRequest`
- **Etkilenen:** NetDespatch (418-41), Netbook (1441-39)

## TASK-XSS-09 — `MainMaster_NoFrames` (`main_noframes.master.cs` 74)
- **Konum:** `DigitalPlanet.NetInvoice.Web.dll` → `main_noframes.master.cs` satır 74
- **Etkilenen:** NetInvoiceWebPortal (1473-20), NetInvoiceWebServices (128-22)

## TASK-XSS-10 — `MainMaster_NoFrames.OnLoad` (%10)
- **Konum:** `DigitalPlanet.NetInvoice.Web.dll` → `NetInvoice.Web.MainMaster_NoFrames.OnLoad`
- **Etkilenen:** NetReceipt (1131-24)

## TASK-XSS-11 — Handler dosyaları (`.ashx.cs`) — modül-özel
- `sevoucherexport.ashx.cs` 219 → NetSeVoucher (2351-3)
- `downloadreceiptreport.ashx.cs` 69 → NetReceipt (1202-1)
- `downloadreceiptreporthandler.ashx.cs` 72 → NetReceipt (1201-2)
- `receiptexport.ashx.cs` 185 → NetReceipt (1200-3)
- `getnetbookhandler.ashx.cs` 280 → Netbook (12-1)

## TASK-XSS-12 — Login sayfası statik JS/HTML (WebPortal)
- **Konum:** `JS files within WebPortal-20260619.1.zip` → `Login/index.html`, `Login/en/index.html`, `Login/js/owl.carousel.js`
- **Etkilenen:** NetInvoiceWebPortal (1406/1400/1407/60/1401/1404/1405/1408 + owl.carousel.js 238/393/510/1154/1223/1227/1280)
- **Not:** `RequestValidationError.aspx.cs` 22 (NetInvoiceWebServices 1548-24) da bu gruba dâhildir.
