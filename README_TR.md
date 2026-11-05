# RustWard

Bağımsız (çevrimdışı) Windows 10 Pro iş istasyonları için USB depolama erişim denetimi.

> **Mevcut durum: Faz 0 tamamlandı, Faz 1 temeli (salt okunur).**
> RustWard şu anda **hiçbir şeyi engellemez**. Tüm çıktılar simülasyondur ve bunu açıkça belirtir.

## Bugün neler var

- `rustward-core` — saf Rust iş mantığı: Windows PnP kimlik ayrıştırma, üretici kataloğu,
  iş istasyonu bazlı marka politikası (varsayılan: reddet), aygıt sınıflandırma, kanıtlı
  karar üretimi ve Faz 2'de test edilecek Windows "Aygıt Yükleme Kısıtlamaları"
  yapılandırmasının *önizlemesi*.
- `rustward-windows` — SetupAPI ile salt okunur aygıt envanteri.
- `rustward-enforcement` — dürüst koruma durumu türleri; henüz uygulama (enforcement) sağlayıcısı yok.
- `rustward-inventory` — salt okunur komut satırı aracı.

## Hızlı başlangıç (Windows, MSVC araç zinciri)

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\check-prereqs.ps1   # salt okunur ortam raporu
cargo test --workspace
cargo run -p rustward-inventory -- scan                                  # canlı, salt okunur
cargo run -p rustward-inventory -- evaluate --snapshot tests\fixtures\synthetic-lab-snapshot.json
cargo run -p rustward-inventory -- plan --live                           # önizleme, asla uygulanmaz
```

## Fizibilite özeti

Windows'un marka düzeyinde uygulayabildiği tek tanımlayıcı, aygıt yazılımının bildirdiği
SCSI INQUIRY üretici alanıdır (ör. `USBSTOR\DiskSanDisk_`). Aday mekanizma, katmanlı
değerlendirmeli Windows Aygıt Yükleme Kısıtlamalarıdır. Bu yöntem:

- taklit edilmeye (spoofing) karşı korumalı **değildir**;
- daha önce yüklenmiş aygıtları yeniden değerlendirmez (önce denetimli temizlik gerekir);
- genel denetleyici adı (ör. "Generic", "JMicron") bildiren ürünlerde marka tanıyamaz.

TÜBİTAK SIR II tanımlayıcıları fiziksel inceleme yapılana kadar bilinmiyor; o zamana kadar
bu aygıtlar varsayılan olarak reddedilir.

Öneri: yalnızca izole test bilgisayarında Faz 2 kavram kanıtı için **KOŞULLU EVET (CONDITIONAL GO)**.
Ayrıntılar: [`docs/ENFORCEMENT-FEASIBILITY.md`](docs/ENFORCEMENT-FEASIBILITY.md) (İngilizce).

## Bildirim metinleri

- Doğrulanmış engelleme: **"USB engellenmiştir. İşlem kayıt altına alınmıştır."**
  (yalnızca uygulama mekanizması kanıt ürettiğinde gösterilir)
- Doğrulanamayan durum: "Koruma doğrulanamadı: bu USB depolama aygıtının engellendiği teyit edilemedi."

## Güvenlik kuralları

Geliştirme bilgisayarında veya üretimdeki iş istasyonlarında Windows güvenlik politikası
değiştirmeyin, sürücü yüklemeyin, aygıt devre dışı bırakmayın. Faz 2 denemeleri yalnızca
imajı alınmış, izole bir test bilgisayarında ve yazılı onayla yapılır.
