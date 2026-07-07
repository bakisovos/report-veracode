# Cryptographic Issues (CWE-327, 331, 329, 780, 321)

**Kategori:** Cryptographic Issues

## Genel Çözüm Önerisi
Amaca uygun kriptografi seçin; proprietary/"security through obscurity" algoritmalardan kaçının. Yüksek güvenlik için 256-bit simetrik, 2048-bit asimetrik anahtar. Anahtar saklama best-practice'lerini uygulayın; plaintext veri ve anahtar materyali ifşa olmasın.

---

# CWE-327 — Use of a Broken or Risky Cryptographic Algorithm
**Effort to Fix:** 1 (≤5 satır, ≤1 saat) · **Exploitability:** Likely

## TASK-CRYPTO-327-01 — `DigitalPlanet.NetInvoice.Communication.CreateMD5HashFtomByte` (%17)
- **Konum:** `DigitalPlanet.NetInvoice.dll` → `Communication.CreateMD5HashFtomByte(byte[])` (`communication.cs` 1146)
- **Etkilenen:** NetSeVoucher (854-7), NetReceipt (936-13), NetDespatch (6-14), NetInvoiceDLL (33-2), NetInvoiceWindowsServices (17960-3), NetInvoiceWebPortal (1445-5), NetInvoiceWebServices (2061-5), Netbook (865-13)

## TASK-CRYPTO-327-02 — `DigitalPlanet.Core...MD5Hasher.Create` (%83)
- **Konum:** `DigitalPlanet.Core.dll` → `Core.Security.Cryptography.MD5Hasher.Create()`
- **Etkilenen:** NetSeVoucher (865-5), NetReceipt (934-11), NetDespatch (3-11), NetInvoiceDLL (42-3), NetInvoiceWindowsServices (33-4), NetInvoiceWebPortal (123-10), NetInvoiceWebServices (12-11), Netbook (867-12)

## TASK-CRYPTO-327-03 — `NetInvoice.Web...BaBsResult.Decrypt` (%33)
- **Konum:** `DigitalPlanet.NetInvoice.Web.dll` → `NetInvoice.Web.NetInvoice.BaBsResult.Decrypt(string)`
- **Etkilenen:** NetSeVoucher (1027-18), NetReceipt (1148-25), NetDespatch (114-37), Netbook (1454-40), NetInvoiceWebPortal (358-3 `babsresult.aspx.cs` 32), NetInvoiceWebServices (126-3 aynı)

## TASK-CRYPTO-327-04 — `EdocLib.Util.GetHash` (%59)
- **Konum:** `EdocLib.dll` → `EBG.EdocLib.Util.GetHash(EdocService.HashType, byte[])`
- **Etkilenen:** NetReceipt (1164-33), NetInvoiceDLL (856-4), NetInvoiceWebPortal (97-13), NetInvoiceWebServices (2076-14), Netbook (8137-50)

## TASK-CRYPTO-327-05 — `DigitalLibrary.Security.SecurityTool.HashPassword` (%35/40)
- **Konum:** `DigitalLibrary.Security.dll` → `Security.SecurityTool.HashPassword(string, PasswordFormat)` (`securitytool.cs` 32/33)
- **Etkilenen:** NetReceipt (106-6/105-6), NetDespatch (165-6/164-6), DigitalLibrary (11-4/12-4), NetInvoiceWebPortal (108-5/1414-5), NetInvoiceWebServices (10-5/1894-5), Netbook (85-6/84-6)

## TASK-CRYPTO-327-06 — `DigitalLibrary.Cryptography.TDESEncryption.Encrypt/Decrypt` (%0/24/26/40/43)
- **Konum:** `DigitalLibrary.Security.dll` → `Cryptography.TDESEncryption` (`Encrypt`/`Decrypt`)
- **Etkilenen:** NetReceipt (939-944-5), NetDespatch (169-174-5, 20-22-12 via `DigitalPlanet.Core...TDESEncryption`), Netbook (868-873-5)

## TASK-CRYPTO-327-07 — `NetInvoice.Task...BABSReportTemplate.Encrypt` (%32)
- **Konum:** `DigitalPlanet.NetInvoice.Task.dll` → `Task.BABSReport.BABSReportTemplate.Encrypt(string)` (`babsreporttemplate.cs` 267)
- **Etkilenen:** NetReceipt (1182-18), NetDespatch (59-23), NetInvoiceWindowsServices (327-2), NetInvoiceWebPortal (384-2), NetInvoiceWebServices (151-2), Netbook (1330-25)

## TASK-CRYPTO-327-08 — `NetInvoice.Integration.CreateMD5HashFromString` (%30) — Netbook özel
- **Konum:** `DigitalPlanet.NetInvoice.dll` → `Integration.CreateMD5HashFromString(string)`
- **Etkilenen:** Netbook (1343-18)

## TASK-CRYPTO-327-09 — `NetInvoice.CustomerPreApplyForm.GenerateCustomerToken` (%64) — Netbook özel
- **Konum:** `DigitalPlanet.NetInvoice.dll` → `CustomerPreApplyForm.GenerateCustomerToken()`
- **Etkilenen:** Netbook (1437-15)

## TASK-CRYPTO-327-10 — `SovosMW.EArchive.Core...DocumentRequestModel` — Middleware özel
- **Konum:** `SovosMW.EArchive.Core.dll` → `documentrequestmodel.cs` 38
- **Etkilenen:** IST_DTP_EARC_Middleware (1-1) — **grace period dolmuş [15.01.2025]**

## TASK-CRYPTO-327-11 — `DP.GIBRouter.Core...Helper` — GIBRouter özel
- **Konum:** `DP.GIBRouter.Core.dll` → `helper.cs` 43
- **Etkilenen:** IST_Dtp-GIBRouterWebServices (2-1) — **grace period dolmuş [21.05.2024]**

---

# CWE-331 — Insufficient Entropy
**Effort to Fix:** 2 · **Exploitability:** Unlikely

## TASK-CRYPTO-331-01 — `EdocLib` → `BouncyCastle.BigInteger.!ctor` (%57)
- **Konum:** `EdocLib.dll` → `Org.BouncyCastle.Math.BigInteger.!ctor(int, System.Random)`
- **Etkilenen:** NetSeVoucher (856-23), NetReceipt (935-34), NetInvoiceDLL (861-5), NetInvoiceWindowsServices (36-6), NetInvoiceWebPortal (179-14), NetInvoiceWebServices (2060-15), Netbook (863-51)

## TASK-CRYPTO-331-02 — `NetInvoice.Web.Handlers.ResourceMonitor.ProcessRequest` (%46/57)
- **Konum:** `DigitalPlanet.NetInvoice.Web.dll` → `Handlers.ResourceMonitor.ProcessRequest`
- **Etkilenen:** NetSeVoucher (1037/1036/1038-14), NetDespatch (122/121/123-31), Netbook (1271/1448/1272-35)

## TASK-CRYPTO-331-03 — `NetInvoice.Web.UserControl.BannerControl.LoadBanner` (%14)
- **Konum:** `DigitalPlanet.NetInvoice.Web.dll` → `UserControl.BannerControl.LoadBanner()`
- **Etkilenen:** NetSeVoucher (1055-22), NetDespatch (111-42), Netbook (1438-47)

## TASK-CRYPTO-331-04 — `DigitalLibrary.RandomStringGenerator.GenerateHexadecimalNumbers[WithoutZero]` (%67/68)
- **Konum:** `DigitalLibrary.dll` → `RandomStringGenerator`
- **Etkilenen:** NetReceipt (1123/1124-4), NetDespatch (430/1762-4), NetInvoiceWebPortal (88/89-4), NetInvoiceWebServices (84/2120-4), Netbook (1433/1434-4)

## TASK-CRYPTO-331-05 — `DigitalLibrary.Security.UserVerificationCode.<CodeGenerate>b__0` (%93)
- **Konum:** `DigitalLibrary.Security.dll` → `Security.UserVerificationCode...<CodeGenerate>b__0(int)`
- **Etkilenen:** NetReceipt (4213-7), NetDespatch (7120-7), NetInvoiceWebPortal (1461-6), NetInvoiceWebServices (2109-6), Netbook (10932-7)

## TASK-CRYPTO-331-06 — `edoclib...BigInteger.!ctor` (`digitalplanet.netinvoice.dll/edoclib.dll`) — NetInvoiceDLL/EGA
- Bu, TASK-CRYPTO-331-01 ile aynı sınıf/metottur; farklı çağıran modüller üzerinden görünür (dedup edildi).

---

# CWE-329 — Generation of Predictable IV with CBC Mode
**Effort to Fix:** 2 · **Severity:** Low · **Exploitability:** Neutral

## TASK-CRYPTO-329-01 — `DigitalLibrary.Cryptography.AESEncryption.Decrypt / DecryptString` (%49/47)
- **Konum:** `DigitalPlanet.NetInvoice.dll` → `DigitalLibrary.Cryptography.AESEncryption` (`aesencryption.cs` 52 & 110)
- **Etkilenen:** NetSeVoucher (2329/2330-6), NetReceipt (4145/4146-12), NetDespatch (6996/6997-13), NetInvoiceDLL (1350/1349-1), NetInvoiceWindowsServices (25209/25208-1), NetInvoiceWebPortal (2533/2532-1), NetInvoiceWebServices (4915/4914-1)

---

# CWE-780 — Use of RSA Algorithm without OAEP
**Effort to Fix:** 2 · **Exploitability:** Neutral

## TASK-CRYPTO-780-01 — `ReportDocument.EncryptString` (%98) — Netbook
- **Konum:** `DigitalPlanet.NetInvoice.dll` → `ReportView.ReportDocument.EncryptString(string)`
- **Etkilenen:** Netbook (866-20)

## TASK-CRYPTO-780-02 — `producerssevouchersummary.cs` 366 / `sevoucherreportcreatorbusiness.cs` 563 — NetSeVoucher
- **Konum:** `DP.NetSeVoucher.SeVoucherDataLibrary.dll` (`producerssevouchersummary.cs` 366) ve `SeVoucherReportCreateLibrary.dll` (`sevoucherreportcreatorbusiness.cs` 563) ve `signpdfservice_new` (`pdfjob.cs` 1016)
- **Etkilenen:** NetSeVoucher (8-1, 4-2, 3-4) — **grace period dolmuş [14.08.2024]**
- **Not:** NetInvoiceWindowsServices/WebPortal/WebServices'te aynı `ReportDocument` (`reportdocument.cs` 55) CWE-780 bulgusu **son taramada düzelmiş** (Appendix A'da "not detected").

---

# CWE-321 — Use of Hard-coded Cryptographic Key
**Effort to Fix:** 4 · **Exploitability:** Likely

## TASK-CRYPTO-321-01 — `hiltondatamanager.aspx.cs` 1
- **Konum:** `DigitalPlanet.NetInvoice.Web.dll` → `hiltondatamanager.aspx.cs` satır 1
- **Etkilenen:** NetInvoiceWebPortal (1377-10), NetInvoiceWebServices (1785-11)
