# RustWard

Bağımsız (çevrimdışı) Windows 10 Pro x64 iş istasyonları için marka tabanlı USB depolama
erişim denetimi.

> **Mevcut durum (2026-11-06): geliştirme sürümü, yalnızca simülasyon.**
> RustWard **hiçbir USB aygıtını engellemez**. Tüm kararlar simülasyondur
> (`SİMÜLE İZİN` / `SİMÜLE RET`) ve genel bakış ekranı
> **"Koruma henüz gerçek Windows ortamında doğrulanmadı."** uyarısını gösterir. Yerel Windows
> ve fiziksel USB testleri son kabul aşamasına ertelenmiştir. Üretime hazır değildir.

## Neler var

| Bileşen | Yol | Durum |
|---|---|---|
| Politika motoru | `crates/rustward-core` | Test edildi |
| SQLite depolama, zincirli denetim kaydı | `crates/rustward-storage` | Test edildi |
| Uygulama hizmeti (tüm istekler) | `crates/rustward-app` | Test edildi |
| Windows hizmeti | `crates/rustward-service` | Konsol modu test edildi; SCM derlenmedi/doğrulanmadı |
| Kuru çalıştırma uygulama sağlayıcıları | `crates/rustward-enforcement` | Model olarak test edildi; **engelleme yok** |
| Yerel IPC (sahte taşıyıcı + adlandırılmış kanallar) | `crates/rustward-ipc` | Protokol test edildi; kanallar yalnızca tür denetiminden geçti |
| Salt okunur SetupAPI envanteri | `crates/rustward-windows`, `crates/rustward-inventory` | Mantık test edildi; yerel çalıştırma YAPILMADI |
| Masaüstü uygulaması (Tauri 2, React, TS, Tailwind) | `apps/rustward-desktop` | Arayüz test edildi; Tauri kabuğu yalnızca Linux'ta test edildi |
| Uygulama için arka uç seçimi | `crates/rustward-ui-bridge` | Test edildi |
| Çevrimdışı paketleme hazırlığı | `scripts/`, `packaging/` | Bağımlılık arşivleme Linux'ta test edildi; MSI YAPILMADI |

Ayrıntılar ve sınıflandırma: [`docs/PHASE-STATUS.md`](docs/PHASE-STATUS.md).
Test kanıtları: [`docs/TEST-RESULTS.md`](docs/TEST-RESULTS.md).

## Geliştirme

```bash
./scripts/verify-all.sh                       # fmt, clippy, tüm testler, arayüz tür denetimi/testler/derleme

cd apps/rustward-desktop && npm ci
npm test                                      # Vitest
npx tauri dev                                 # hata ayıklama sürümü: süreç içi geliştirme arka ucu, geçici veritabanı
```

Hata ayıklama sürümü bir geliştirme arka ucu kullanır (geçici veritabanı, sentetik yönetici,
hizmetle aynı doğrulama ve yetkilendirme kodu). Yayın sürümleri her zaman Windows
hizmetiyle konuşur; geliştirme arka ucu bu sürümlere derlenemez.

Windows (MSVC araç zinciri), salt okunur:

```powershell
cargo test --workspace
cargo run -p rustward-inventory -- scan
cargo run -p rustward-service -- console      # geçici veritabanı, sentetik envanter, kurulum yok
```

Hizmeti geliştirme bilgisayarına asla kurmayın veya kaydetmeyin. Paketleme:
[`docs/OFFLINE-DEPLOYMENT.md`](docs/OFFLINE-DEPLOYMENT.md).

## Tek paragrafta uygulanabilirlik

Windows'un marka düzeyinde uygulayabildiği tek tanımlayıcı SCSI INQUIRY üretici dizesidir;
`USBSTOR\DiskSanDisk_` gibi üretici düzeyinde bir donanım kimliği olarak görünür. Aday
mekanizma, katmanlı değerlendirmeli Windows "Aygıt Yükleme Kısıtlamaları"dır. Sahteciliğe
karşı dayanıklı değildir, önceden yüklenmiş aygıtları yeniden değerlendirmez ve genel bir
denetleyici adı bildiren ürünlere yardımcı olamaz. TÜBİTAK SIR II tanımlayıcıları hâlâ
bilinmiyor. Bkz. [`docs/ENFORCEMENT-FEASIBILITY.md`](docs/ENFORCEMENT-FEASIBILITY.md).

## Belgeler

| Belge | İçerik |
|---|---|
| [PHASE-STATUS](docs/PHASE-STATUS.md) | Kilometre taşları, sınıflandırma, eksikler, işlemeler |
| [TEST-RESULTS](docs/TEST-RESULTS.md) | Nerede ne test edildi, neler ERTELENDİ |
| [ARCHITECTURE](docs/ARCHITECTURE.md) | Crate'ler, güven sınırları, IPC sözleşmesi |
| [SECURITY-MODEL](docs/SECURITY-MODEL.md) / [THREAT-MODEL](docs/THREAT-MODEL.md) | Yetki ayrımı, kanallar, Tauri sıkılaştırması |
| [KNOWN-LIMITATIONS](docs/KNOWN-LIMITATIONS.md) | Kalan riskler L-01…L-21 |
| [OFFLINE-DEPLOYMENT](docs/OFFLINE-DEPLOYMENT.md) | Arşivleme, MSI, WebView2, kurulum/kaldırma |

Belgelerin ayrıntılı sürümleri İngilizcedir.

## Katkıda bulunanlar için güvenlik kuralları

Geliştirme bilgisayarında veya herhangi bir üretim iş istasyonunda Windows güvenlik
politikasını değiştirmeyin, sürücü kurmayın, aygıtları devre dışı bırakmayın ve hizmeti
kaydetmeyin. Uygulama (engelleme) deneyleri yalnızca yazılı onayla, yalıtılmış ve imajı
alınmış bir kabul sanal makinesinde yapılır.
