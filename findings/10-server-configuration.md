# Server Configuration (CWE-16, CWE-693)

**Kategori:** Server Configuration · **Effort to Fix:** 1 · **Exploitability:** Neutral · **Severity:** Low/Medium

## Açıklama
Sunucu/uygulama yapılandırmasındaki eksikler güvenlik zafiyeti doğuruyor: eksik güvenlik başlıkları (security headers), güvensiz cookie ayarları, gereksiz açık debug/trace, protection mekanizmalarının devre dışı olması.

## Çözüm Önerisi
Güvenlik başlıklarını ekleyin (`X-Content-Type-Options: nosniff`, `X-Frame-Options`, `Content-Security-Policy`, `Strict-Transport-Security`). Cookie'lerde `HttpOnly` ve `Secure` bayraklarını açın. Production'da `debug=false`, `trace enabled=false`. Gereksiz HTTP metotlarını kapatın.

---

## TASK-SRVCFG-01 (CWE-693) — Eksik güvenlik başlıkları
- **Konum:** `web.config` / IIS response header yapılandırması
- **Etkilenen:** NetInvoiceWebPortal, NetInvoiceWebServices ve tüm web portalleri
- **Aksiyon:** `X-Content-Type-Options`, `X-Frame-Options`, `CSP`, `HSTS` ekle

## TASK-SRVCFG-02 (CWE-16) — Güvensiz cookie / debug ayarları
- **Konum:** `web.config` → `<httpCookies httpOnlyCookies="true" requireSSL="true" />`, `<compilation debug="false" />`, `<trace enabled="false" />`
- **Etkilenen:** Tüm web uygulamaları
- **Aksiyon:** Cookie bayraklarını ve production compile ayarlarını sıkılaştır
