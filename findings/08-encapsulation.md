# Encapsulation (CWE-501) — Trust Boundary Violation

**Kategori:** Encapsulation · **CWE:** 501 · **Effort to Fix:** 2 · **Exploitability:** Neutral

## Açıklama
Trusted ve untrusted veriler aynı veri yapısında (ör. `HttpSession`) karıştırılıyor. Bir trust boundary üzerinden güven sınırı ihlali oluşuyor; untrusted veri trusted gibi ele alınıp yetki/veri bütünlüğü riskleri doğuyor.

## Çözüm Önerisi
Trust boundary'yi net tutun: session'a yazmadan önce untrusted input'u doğrulayın/temizleyin. Trusted ve untrusted veriyi ayrı yapılarda saklayın. Session'a konan kullanıcı kaynaklı değerleri yetki kararlarında kullanmadan önce yeniden doğrulayın.

---

## TASK-ENCAP-01 — Session'a doğrulanmamış input yazımı
- **Konum:** `DigitalPlanet.NetInvoice.Web.dll` → session'a kullanıcı girdisini doğrudan yazan sayfa/handler'lar
- **Etkilenen:** NetInvoiceWebPortal, NetInvoiceWebServices ve ortak web modülünü kullanan portaller
- **Aksiyon:** Session'a yazımdan önce input validation ekle; trust boundary'yi belgelendir
