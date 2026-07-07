# Veracode Bulguları — Konsolide Rapor (Tekilleştirilmiş / Task Bazlı)

> **Hazırlanma tarihi:** 07 Temmuz 2026
> **Kaynak:** 15 adet Veracode Detailed Report (Sovos Compliance — Sovos Global EMEA policy)
> **Kapsam:** Yalnızca Static Scan bulguları. Informational (Code Quality / Potential Backdoor dâhil) bulgular da task olarak eklenmiştir.

## Bu rapor nasıl okunur?

- Bulgular **ana başlıklar altında (CWE / kategori)** gruplandı.
- **Aynı bulgu** = aynı **CWE + aynı sınıf/metot veya dosya:satır** → **tek task** olarak birleştirildi (dedup).
- Her task'ta o bulgunun **hangi uygulamalarda/raporlarda** göründüğü listelenir → bilgi kaybı yok.
- Bulguların çoğu **ortak modüllerde** (`DigitalLibrary.dll`, `DigitalPlanet.NetInvoice.dll`, `EdocLib.dll`, `DigitalPlanet.Core.dll`, `DigitalLibrary.Web.dll`, `DigitalLibrary.Security.dll`, `DP.NewUserGbList.dll` vb.) yer aldığı için bir ortak modül düzeltmesi **birçok uygulamayı aynı anda** kapatır.

---

## Uygulama (Proje) Envanteri

| # | Uygulama | Skor | Rating | Policy | Medium | Low | Info |
|---|----------|:----:|:------:|--------|:------:|:---:|:----:|
| 1 | IST_Dtp-NetSeVoucherWebPortal | 89 | A | Did Not Pass | 29 | 14 | 5 |
| 2 | IST_Dtp-NetReceiptWebPortal | 82 | B | Did Not Pass | 55 | 14 | 3 |
| 3 | IST_Dtp-NetAsyncProcess | 99 | A | **Pass** | 0 | 4 | 0 |
| 4 | IST_DTP_EINV_Middleware | 100 | A | Did Not Pass¹ | 0 | 0 | 4 |
| 5 | IST_DTP_EARC_Middleware | 99 | A | Did Not Pass | 1 | 0 | 0 |
| 6 | IST_DTP_DOC_Middleware | 100 | A | Did Not Pass¹ | 0 | 0 | 0 |
| 7 | IST_Dtp-NetDespatchWebPortal | 73 | C | Did Not Pass | 105 | 24 | 2 |
| 8 | IST_Dtp-GIBRouterWebServices | 99 | A | Did Not Pass | 1 | 0 | 0 |
| 9 | IST_Dtp_DigitalLibrary | 93 | A | Did Not Pass | 18 | 5 | 2 |
| 10 | IST_DTP_NetInvoice_NetInvoiceDLL | 96 | A | Did Not Pass | 8 | 6 | 1 |
| 11 | IST_Dtp-NetInvoiceWindowsServices | 91 | A | Did Not Pass | 19 | 22 | 2 |
| 12 | IST_Dtp-NetInvoiceWebPortal | 78 | B | Did Not Pass | 74 | 20 | 3 |
| 13 | IST_Dtp-NetInvoiceWebServices | 79 | B | Did Not Pass | 69 | 15 | 3 |
| 14 | IST_DTP_NetInvoice_SCA | 100 | A | Conditional Pass¹ | 0 | 0 | 0 |
| 15 | IST_Dtp-NetbookWebPortal | 70 | C | Did Not Pass | 126 | 14 | 5 |

¹ Kod bulgusu değil; **SCA / lisans (Disallow Vulnerabilities by Severity / License Risk)** kuralından dolayı "Did not pass / Conditional".

**Öncelik sırası (skora göre en kritik):** #15 Netbook (70) → #7 NetDespatch (73) → #12 NetInvoiceWebPortal (78) → #13 NetInvoiceWebServices (79) → #2 NetReceipt (82).

---

## Ana Başlıklar (Kategori) Özeti

| Kategori | CWE | Benzersiz Task | Etkilenen Uygulama Sayısı |
|----------|-----|:--------------:|:-------------------------:|
| CRLF Injection | 117 | 3 | 9 |
| Credentials Management | 798, 259 | 4 | 4 |
| Cross-Site Scripting (XSS) | 80 | 12 | 6 |
| Cryptographic Issues | 327, 331, 329, 780, 321 | 18 | 12 |
| Directory Traversal | 73 | 28 | 6 |
| Information Leakage | 209, 201, 918 | 12 | 12 |
| Insufficient Input Validation | 90, 601, 470 | 5 | 8 |
| Time and State | 377 | 1 | 2 |
| Code Quality (Info) | 404 | 5 | 8 |
| Potential Backdoor (Info) | 656 | 4 | 8 |

> Ayrıntılı, tekilleştirilmiş task listeleri **`findings/`** klasöründeki dosyalarda:
>
> - [`findings/01-crlf-injection.md`](findings/01-crlf-injection.md)
> - [`findings/02-credentials-management.md`](findings/02-credentials-management.md)
> - [`findings/03-xss.md`](findings/03-xss.md)
> - [`findings/04-cryptographic-issues.md`](findings/04-cryptographic-issues.md)
> - [`findings/05-directory-traversal.md`](findings/05-directory-traversal.md)
> - [`findings/06-information-leakage.md`](findings/06-information-leakage.md)
> - [`findings/07-insufficient-input-validation.md`](findings/07-insufficient-input-validation.md)
> - [`findings/08-time-and-state.md`](findings/08-time-and-state.md)
> - [`findings/09-code-quality-info.md`](findings/09-code-quality-info.md)
> - [`findings/10-potential-backdoor-info.md`](findings/10-potential-backdoor-info.md)

---

## En Yüksek Etkili Ortak Modül Düzeltmeleri (Fix-First)

Bu tablodaki her satır **tek bir düzeltme** ile **birden fazla uygulamayı** iyileştirir:

| Ortak Modül | Sınıf / Metot | CWE | Etki |
|-------------|---------------|-----|------|
| `DigitalLibrary.dll` | `FileLogger.Write` | 117 | CRLF — neredeyse tüm uygulamalar |
| `DigitalPlanet.NetInvoice.dll` | `Communication.CreateMD5HashFtomByte` | 327 | Zayıf MD5 — çok sayıda uygulama |
| `DigitalPlanet.Core.dll` | `MD5Hasher.Create` | 327 | Zayıf MD5 |
| `DigitalLibrary.Security.dll` | `TDESEncryption.Encrypt/Decrypt`, `SecurityTool.HashPassword` | 327 | Zayıf kripto |
| `DigitalPlanet.NetInvoice.dll` | `AESEncryption.Decrypt/DecryptString` | 329 | Öngörülebilir IV |
| `EdocLib.dll` | `BouncyCastle.BigInteger.!ctor` | 331 | Zayıf entropi |
| `DigitalLibrary.Web.dll` | `AuthenticationHelper` (AD) | 90 | LDAP Injection |
| `DigitalLibrary.Web.dll` | `WebSettings.Save` | 73 | Path traversal (12 instance) |
| `DigitalPlanet.NetInvoice.Web.dll` | `LoginAnyAccount.LoginButton_Click` | 601 | Open Redirect |
| `DigitalPlanet.NetInvoice.dll` | `ReportView.ReportDocument.!cctor` | 656 | Security through obscurity |
| `DP.NewUserGbList.dll` | `UserListXmlParser.Parse` | 404 | Kaynak sızıntısı |

---

_Bu rapor 15 Veracode raporundan otomatik olarak konsolide edilmiştir. Tüm bulgular korunmuş, tekrar edenler tek task altında birleştirilmiştir._
