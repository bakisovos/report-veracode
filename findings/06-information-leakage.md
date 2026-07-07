# Information Exposure / Leakage (CWE-200, CWE-209, CWE-497)

**Kategori:** Information Leakage · **Effort to Fix:** 2–3 · **Exploitability:** Neutral

## Açıklama
Uygulama, hata mesajları / debug çıktıları / sistem verileri aracılığıyla saldırganın işine yarayacak hassas bilgileri (stack trace, iç yol, config, sürüm) ifşa ediyor. Bu bilgiler sonraki saldırıların planlanmasını kolaylaştırır.

## Çözüm Önerisi
Kullanıcıya dönen hata mesajlarını generic tutun; ayrıntılı hata/stack trace'i yalnızca sunucu tarafı loglara yazın. `customErrors mode="On"` / production'da debug kapalı. İç sistem bilgilerini (dosya yolu, connection string, sürüm) yanıtlara koymayın.

---

## TASK-INFOLEAK-01 (CWE-209) — Hata mesajıyla bilgi ifşası · `Layouts.GetError.Page_Load`
- **Konum:** `DigitalPlanet.NetInvoice.Web.dll` → `NetInvoice.Web.Layouts.GetError.Page_Load`
- **Etkilenen:** NetSeVoucher, NetDespatch, Netbook (ortak modül)

## TASK-INFOLEAK-02 (CWE-200) — Hassas veri ifşası · `Communication` katmanı
- **Konum:** `DigitalPlanet.NetInvoice.dll` → `Communication` sınıfı log/exception çıktıları
- **Etkilenen:** Tüm portaller (ortak `DigitalPlanet.NetInvoice.dll`)

## TASK-INFOLEAK-03 (CWE-497) — Sistem verisi ifşası · `web.config` / debug
- **Konum:** Web uygulamalarının `web.config` (customErrors, debug ayarları)
- **Etkilenen:** NetInvoiceWebPortal, NetInvoiceWebServices ve diğer web portalleri
- **Aksiyon:** Production build'lerde `debug="false"`, `customErrors mode="RemoteOnly"` doğrulanmalı
