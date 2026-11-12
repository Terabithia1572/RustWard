# RustWard

**Windows 10/11 Pro için çevrimdışı USB depolama erişim denetimi ve Windows Yerel Grup İlkesi uygulama aracı.**

[English](README.md) · Geliştirici: **Yunus İNAN**

> **Durum (V1.0.0, Kasım 2026): Sanal makinede doğrulanmış sürüm (üretim ortamı sertifikasyonu henüz yapılmamıştır).**
>
> - RustWard, üretici temelli USB depolama kurallarını (`İzinli` / `Açıkça Reddet`) yönetir ve doğrulanmış donanım kimliklerini kalıcı **Windows Yerel Grup İlkesi (`IGroupPolicyObject`)** kısıtlamalarına (`DeviceInstall\Restrictions`) derler.
> - Yalıtılmış bir Windows 10 Pro 22H2 (Derleme 19045) VMware sanal makinesinde eşzamanlı **Kingston DataTraveler 3.0 (USBSTOR)** ve **SanDisk 3.2Gen1 (UASP/SCSI)** engellemesi, Kingston engelli kalırken **SanDisk İzin / Reddet geçişleri** ve temiz ilke geri alma işlemleri doğrulanmıştır.
> - Üretici kimliği cihazların bildirdiği USB tanımlayıcıları ve SCSI `INQUIRY` alanlarına dayanır; kriptografik olarak doğrulanmaz.
> - Tam ayrıcalıklı USB engellemesi için `RustWardService` Windows hizmetinin kurulu olması ve Windows Yönetici yetkileri gereklidir.
> - Dahili sistem diskleri (NVMe/SCSI), VMware sanal diskleri ve HID giriş birimleri (klavye/fare) kısıtlamalardan ve yeniden başlatmalardan hariç tutulur.

## İçindekiler

- [Genel bakış](#genel-bakış)
- [Özellikler](#özellikler)
- [Güvenlik modeli](#güvenlik-modeli)
- [Mimari](#mimari)
- [Teknoloji yığını](#teknoloji-yığını)
- [Desteklenen Windows sürümleri](#desteklenen-windows-sürümleri)
- [Kurulum](#kurulum)
- [Derleme](#derleme)
- [Testler](#testler)
- [Bilinen sınırlamalar](#bilinen-sınırlamalar)
- [Belgeler](#belgeler)

## Genel bakış

RustWard, harici USB depolama birimlerinin ağ bağlantısı veya üçüncü taraf çekirdek sürücüsü olmaksızın üretici temelinde denetlenmesi gereken bağımsız Windows iş istasyonları için tasarlanmıştır:

| Üretici / Kategori | V1.0.0 Desteği | Doğrulama Durumu |
|---|---|---|
| SanDisk (USBSTOR ve UASP/SCSI) | `İzin` / `Reddet` geçişleri | **Windows 10 sanal makinede doğrulandı** |
| Kingston (USBSTOR) | `Reddet` / `İzin` geçişleri | **Windows 10 sanal makinede doğrulandı** |
| Genel Denetleyici Üreticileri (`VendorC`, `Generic`) | `Reddet` / Güvenli sınıflandırma | **Windows 10 sanal makinede doğrulandı** |
| Diğer katalog üreticileri (50+ kayıt) | İlke planlama ve kural derleme | Donanıma bağlı / genel |
| Klavye, fare, dahili NVMe/SCSI diskler | Hiçbir zaman hedeflenmez | **Windows 10 sanal makinede doğrulandı** |

## Özellikler

- **Gerçek Cihaz Envanteri:** SetupAPI üzerinden USB depolama (`USBSTOR` ve `UASPStor` / `SCSI`), çevre birimleri ve dahili disklerin salt okunur envanteri.
- **Birleşik Çoklu Üretici İlke Yöneticisi:**
  - `DenyDeviceIDs` / `AllowDeviceIDs` kurallarını `DenyDeviceIDsRetroactive = 1` ile birlikte tek bir atomik Yerel Grup İlkesi işleminde uygular.
  - İzni verilen USB aygıtları güvenli biçimde yeniden başlatarak depolama erişimini geri kazandırır.
  - Eski Windows ilke durumunu yedekler ve tek işlemle temiz geri alma sağlar.
- **UASP / SCSI ve USBSTOR Zorlaması:**
  - Hem klasik USBSTOR (`USBSTOR\DiskKingston...`) hem modern UASP/SCSI (`SCSI\Disk_____USB_SanDisk_...`) aygıtlarını engeller.
  - `USBSTOR\GenDisk`, `SCSI\Disk`, `SCSI\DISK_____USB` ve joker karakter (`*`) gibi genel veya güvensiz kimlikleri reddeder.
- **Gerçek Windows Gözlemi ve Denetim Günlüğü:**
  - `DeviceInstall\Restrictions` kayıt defteri değerlerini ve SetupAPI PnP hata kodlarını canlı okur.
  - SQLite (WAL) tabanlı, SHA-256 karma zincirli denetim kaydını Windows Uygulama Olay Günlüğü (`RustWard`) ile eşler.
- **Çift Dilli Masaüstü Arayüzü:** Varsayılan Türkçe arayüz (İngilizce dil desteği ile).

## Güvenlik modeli

- **Ayrıcalık ayrımı:**
  - `rustward-service.exe`, `LocalSystem` hesabıyla çalışır ve `%ProgramData%\RustWard` veritabanını yönetir (yalnızca SYSTEM + Administrators erişimli ACL).
  - Masaüstü arayüzü hizmetle adlandırılmış kanallar (`RustWard.Status.v1` ve yalnızca Yönetici yetkili `RustWard.Admin.v1`) üzerinden haberleşir.
  - Yetkisiz kanal istekleri hız sınırına tabi tutulur ve denetim kaydına yazılır.
- **Çekirdek sürücüsü gerektirmez:** Yerleşik Windows Aygıt Yükleme Kısıtlamaları ve `IGroupPolicyObject` COM arayüzünü kullanır.

Ayrıntılar: [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) · [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Mimari

```text
Tauri 2 Masaüstü Uygulaması (React, TypeScript, Tailwind)
  ├──► \\.\pipe\RustWard.Status.v1 (Salt okunur durum ve gözlem)
  └──► \\.\pipe\RustWard.Admin.v1  (Yüksek ayrıcalıklı Yönetici ilke kanalı)
         └──► rustward-service.exe (LocalSystem Windows Hizmeti)
                ├─ rustward-app         istek yönlendirme, GPO uygulama/geri alma
                ├─ rustward-core        üretici kataloğu, politika ve kimlik değerlendirme
                ├─ rustward-enforcement bileşik ilke derleyici ve SetupAPI gözlemcisi
                ├─ rustward-windows     SetupAPI, IGroupPolicyObject COM, Olay Günlüğü
                ├─ rustward-ipc         adlandırılmış kanal doğrulama ve hız sınırı
                └─ rustward-storage     SQLite WAL ve SHA-256 karma zincirli denetim
```

## Teknoloji yığını

Rust (2024 edition), `windows-sys`, `windows-service`, SQLite (`rusqlite` gömülü), Tauri 2, React 19, TypeScript, Tailwind CSS 4, Vitest ve WiX v3 (MSI). Tüm arayüz varlıkları ve `usb.ids` veritabanı tamamen çevrimdışı paketlenir.

## Desteklenen Windows sürümleri

| Öğe | Destek Durumu |
|---|---|
| İşletim sistemi | Windows 10 Pro/Enterprise/Education x64 (22H2 derleme 19045 sanal makinede test edildi); Windows 11 x64 için derlenir. |
| Grup İlkesi motoru | Yerleşik Windows Yerel Grup İlkesi (`gpedit.dll` / `IGroupPolicyObject`) — Pro, Enterprise ve Education sürümleri gereklidir. |
| Çalışma ortamı | Microsoft Edge WebView2 Runtime (MSI içinde çevrimdışı kurucu bulunur), VC++ çalışma zamanı. |
| Ağ bağlantısı | Gerekmez (%100 çevrimdışı). |

## Kurulum

### MSI Kurulum Paketi (Tam Hizmet Koruması İçin Önerilen)

1. `SHA256SUMS.txt` dosyası üzerinden paket özetini (SHA-256) doğrulayın.
2. `RustWard-v1.0.0-x64-Setup.msi` paketini **Yönetici** olarak çalıştırın.
3. Kurulum; masaüstü uygulamasını, `RustWard USB Depolama Denetimi` (`RustWardService`) hizmetini, Olay Günlüğü kaynağını ve korumalı `%ProgramData%\RustWard` dizinini yapılandırır.
4. İlke değişikliği ve uygulama için **RustWard** uygulamasını Yönetici olarak başlatın.

### Taşınabilir Paket (`RustWard-v1.0.0-Portable.zip`)

Tek başına `RustWard.exe` yalnızca yönetim arayüzüdür; `rustward-service.exe` ayrıcalıklı Windows hizmeti olarak kurulmadan tek başına USB cihazlarını engelleyemez. Hizmet kurulumu ve çevrimdışı dağıtım için arşiv içindeki `README-PORTABLE.txt` yönergelerini izleyin.

## Derleme

Windows x64 üzerinde Rust (MSVC 1.90+), Visual Studio C++ Build Tools, Windows SDK, Node.js 22 LTS ve WebView2 ile:

```cmd
BUILD-RUSTWARD.cmd
```

## Testler

```powershell
cargo test --workspace
npm --prefix apps/rustward-desktop test -- --run
```

Doğrulama kanıtları: [docs/ARGON4-PHASED-HOTFIX-ACCEPTANCE.md](docs/ARGON4-PHASED-HOTFIX-ACCEPTANCE.md) ve [docs/TEST-RESULTS.md](docs/TEST-RESULTS.md).

## Bilinen sınırlamalar

- **Sanal makinede doğrulanmış V1.0.0 sürümü:** Yalıtılmış Windows 10 Pro VMware ortamında doğrulanmıştır; kurumsal kod imzalama ve fiziksel saha dağıtımı sonraki aşamalara bırakılmıştır.
- **Kriptografik doğrulama yoktur:** Üretici kimliği cihazın bildirdiği VID/PID ve SCSI `INQUIRY` alanlarına güvenir.
- **Yerel yönetici sınırı:** Yerel Windows yöneticileri Grup İlkesi'ni harici olarak değiştirebilir; RustWard bu sapmayı algılar ve kaydeder.
- **Açılışta otomatik ilke eşitlemesi ve oturum dışı Windows bildirimleri:** V1.1 sürümünde planlanmıştır.

## Belgeler

Mimari tasarım, güvenlik incelemeleri ve kabul test kayıtları [`docs/`](docs/) dizinindedir.
