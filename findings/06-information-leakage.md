# Information Leakage (CWE-209, CWE-201, CWE-918)

**Kategori:** Information Leakage · **CWE:** 209, 201, 918 · **Benzersiz Task:** 12 · **Effort to Fix:** 2–3 · **Exploitability:** Neutral/Likely

## Açıklama
Uygulama, hata mesajları ve yanıtlar aracılığıyla saldırganın işine yarayacak hassas bilgileri ifşa ediyor (CWE-209: hata mesajıyla bilgi sızıntısı, CWE-201: gönderilen veride hassas bilgi). Ayrıca sunucunun kullanıcı tarafından kontrol edilen bir URL'ye istek yapmasına izin veren Server-Side Request Forgery (CWE-918) bulguları mevcuttur.

## Çözüm Önerisi
- **CWE-209/201:** Kullanıcıya dönen hata mesajlarını generic tutun; stack trace / iç yol / sürüm / connection string gibi ayrıntıları yalnızca sunucu loglarına yazın. Production'da `customErrors mode="RemoteOnly"`, `debug="false"`.
- **CWE-918 (SSRF):** Sunucunun istek yapacağı hedef URL'yi whitelist'e bağlayın; kullanıcıdan gelen host/şema/portu doğrulayın, iç ağ (localhost, 169.254.x, private range) hedeflerini engelleyin, redirect'leri takip etmeyin.

---

## TASK-INFOLEAK-01 (CWE-209) — Hata mesajıyla bilgi ifşası · `Layouts.GetError.Page_Load`
- **Konum:** `DigitalPlanet.NetInvoice.Web.dll` → `NetInvoice.Web.Layouts.GetError.Page_Load`
- **Etkilenen:** NetSeVoucher, NetDespatch, Netbook, NetInvoiceWebPortal, NetInvoiceWebServices (ortak modül)

## TASK-INFOLEAK-02 (CWE-209) — Exception detayının yanıta yazılması · `Communication`
- **Konum:** `DigitalPlanet.NetInvoice.dll` → `Communication` katmanı exception çıktıları
- **Etkilenen:** Ortak `DigitalPlanet.NetInvoice.dll` kullanan tüm portaller

## TASK-INFOLEAK-03 (CWE-201) — Hassas verinin yanıtta gönderilmesi
- **Konum:** Rapor/veri dönen handler'lar (`InvoiceExport`, `DownloadEarchiveReport` yanıt başlıkları/gövdeleri)
- **Etkilenen:** NetReceipt, NetDespatch, Netbook, NetInvoiceWebPortal, NetInvoiceWebServices

## TASK-INFOLEAK-04 (CWE-918) — Server-Side Request Forgery
- **Konum:** Dış URL'ye sunucudan istek yapan entegrasyon/proxy metotları (`GetErpData` / ERP çağrıları, rapor çekme)
- **Etkilenen:** NetDespatch, Netbook, NetInvoiceWebServices, Middleware bileşenleri
- **Aksiyon:** Hedef URL whitelist + iç ağ engeli + şema/port doğrulaması

> **Not:** README envanterinde bu kategori 12 task / 12 etkilenen uygulama olarak sayılmıştır; yukarıdaki gruplar dedup edilmiş özet task'lardır. CWE-918 (SSRF) kalemleri exploitability açısından önceliklidir.
