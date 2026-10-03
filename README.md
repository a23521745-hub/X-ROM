# X-ROM

Android 13+ / AOSP tabanlı, GKI ve Project Treble (GSI) uyumlu, yüksek güvenlikli
bir işletim sistemi. X-Defender (eBPF NDR), X-EyeGuard ve kendi kendini onaran
bütünlük mimarisini, **pKVM** (protected KVM) üzerinde çalışan korumalı
sanal makinelerle birleştiren bir ekosistem.

Lisans: Apache-2.0.

---

## Durum

**Oturum 1 + 2 + 3 tamamlandı — temel altyapı, veri düzlemi ve kendi kendini onaran kurtarma.**

Oturum 1 X-ROM'un tüm izolasyon katmanının üzerinde durduğu zemini kurdu: build
ağacında pKVM + AVF etkinleştirme, host ve misafir tarafında SELinux modeli,
izole Microdroid görevleri başlatan native bir C++ servisi. Oturum 2 o VM'in
içine ve dışına akan baytları ekledi: çerçeveli vsock veri düzlemi, payload
imzalama ve çıktının doğrulanması. Oturum 3 cihazın *bozulduğunda* ne yaptığını
ekledi: karantina ve BCB yazımı, `xrom_vault` yedek partition'ı, hibrit kurtarma
karar motoru ve her açılışta çalışan integrity doğrulaması.

| Gereksinim | Nerede | Belge |
|---|---|---|
| pKVM/AVF'yi etkinleştiren `BoardConfig.mk` ve `device.mk` bayrakları | `device/x1/` | [docs/01](docs/01-avf-pkvm-foundation.md) |
| Microdroid için AOSP sistem izinleri ve SELinux yapılandırması | `sepolicy/`, `device/x1/permissions/` | [docs/02](docs/02-selinux-and-permissions.md) |
| İzole Microdroid VM başlatan native C++ servisi | `services/avf/xrom_avfd/` | [docs/03](docs/03-native-service-and-integration.md) |
| Çift yönlü vsock veri düzlemi; payload'ın dış iletişiminin yalnızca bu kanalla sınırlanması | `common/protocol/`, `common/vsock/`, `sepolicy/microdroid/` | [docs/04](docs/04-vsock-data-plane-and-payload-signing.md) §A |
| RSA-4096 / Ed25519 + SHA-256 imza ve ölçüm doğrulaması; imzası doğrulanmayan payload'ın pVM'de çalışmaması | `services/avf/xrom_avfd/PayloadVerifier.*`, `security/payload_trust/`, `tools/xrom_sign_payload.py` | [docs/04](docs/04-vsock-data-plane-and-payload-signing.md) §B |
| `outputDigest` ve dönen verinin doğrulanmış payload tarafından üretildiğinin kanıtlanması | `services/avf/xrom_avfd/IsolationService.cpp`, `aidl/.../IsolationTaskResult.aidl` | [docs/04](docs/04-vsock-data-plane-and-payload-signing.md) §C |
| Tehdit algılandığında `/misc`'e `boot-recovery` yazma, klasörü kilitleme, kanıtı koruma, ağı kesme ve kontrollü reboot | `common/recovery/BcbMessage.*`, `common/recovery/QuarantinePlan.*`, `services/recovery/xrom_sentineld/` | [docs/05](docs/05-self-healing-recovery-and-hybrid-ota.md) §B |
| `xrom_vault` partition'ı ve OTA'yı oraya yazan, ağ erişimi olmayan tek domain | `device/x1/BoardConfig.mk`, `common/recovery/VaultMetadata.*`, `services/ota/xrom_ota_installer/`, `sepolicy/.../xrom_ota_installer.te` | [docs/05](docs/05-self-healing-recovery-and-hybrid-ota.md) §C |
| Ağ sinyaline göre vault ile uzak OTA arasında seçim yapan hibrit karar motoru — **tek bir şüphe vault'a düşürür** | `common/recovery/RecoveryDecision.*`, `bootable/xrom_recovery_gate/` | [docs/05](docs/05-self-healing-recovery-and-hybrid-ota.md) §C.3 |
| Çift Ed25519 + RSA-4096 imza; beyan edilen paket boyutu sınırı; imzaların ROM'a derlenmiş anahtarlara sabitlenmesi | `common/ota/OtaVerifier.*`, `security/ota_trust/`, `tools/xrom_sign_ota.py` | [docs/05](docs/05-self-healing-recovery-and-hybrid-ota.md) §C.4 |
| Her açılışta vault ile koşan slot'un karşılaştırılması; uyuşmazsa kullanıcıya bildirme ve loglama | `common/recovery/VaultMetadata.*` (`CompareImages`), `SentinelService::RunBootChecks` | [docs/05](docs/05-self-healing-recovery-and-hybrid-ota.md) §D |
| Üç başarısız açılışta otomatik recovery — **iki ayrı sayaç**, çünkü platform sayacı post-boot integrity başarısızlığını yapısal olarak göremez | `common/recovery/BootAttemptPolicy.*` | [docs/05](docs/05-self-healing-recovery-and-hybrid-ota.md) §D.4 |

Üçüncü gereksinim hakkında söylenmesi gereken bir şey var ve `docs/04` §C.3'te
uzun uzun yazıldı: çıktıyı doğrulamanın **üç** ayrı gücü var. X-ROM'un gönderdiği
yapılandırma `INSTANCE_BOUND` seviyesine ulaşıyor — host'un sabitlediği
ölçümlerle guest'in VM içinde bağımsız ölçtüğü değerler eşleşiyor ve sonuç
yalnızca o VM instance'ının üretebildiği bir sırla bağlanıyor. Origin'i host'a
kriptografik olarak kanıtlayan `REMOTE_ATTESTED` seviyesi ise RKP, dolayısıyla ağ
erişimi gerektiriyor — yani vsock-only sertleştirme ile aynı anda mümkün değil.
Cihazın erişemediği bir seviyeyi raporlamak, o enum'un hiç olmamasından kötü
olurdu.

Oturum 3 hakkında söylenmesi gereken iki şey var ve ikisi de `docs/05`'te uzun uzun
yazıldı. Birincisi: gelen gereksinimde **15 yerde** değişiklik yapıldı — hiçbiri üslup
tercihi değil, her biri ya build'i kıran ya da bir güvenlik özelliğini çalışıyormuş gibi
gösteren bir sorunun çözümü (`docs/05` §F). İkincisi: bir konu **çözülmedi** ve öyle
bırakıldı — `CONFIG_BPF_SYSCALL` kapalıyken netd'nin bu kernel'de çalışıp çalışmadığı
cihaz olmadan belirlenemez, bu yüzden ağ kesme üç bağımsız katman olarak uygulandı ve
her katman ayrı raporluyor (`docs/05` §F #10 ve §G.1).

Henüz yapılmadı: uzaktan attestasyon, misafir tarafında adanmış SELinux domain'i,
ayrı veri kanalı (`kPortTaskData` ayrılmış ama kullanılmıyor), X-Defender ve
X-EyeGuard entegrasyonu, kanıtın pVM içine taşınması (dondurulmuş isolation AIDL'inde
bunun için bir `TaskClass` yok — `docs/05` §F #14). Kapsam dışı bırakılan her şey ve
gerekçesi `docs/01-avf-pkvm-foundation.md` §8, `docs/04` §E ve `docs/05` §G'de.

---

## Hızlı başlangıç

AOSP ağacı olmadan — politika çekirdeği saf C++17, sistem `g++`'ı ile derleniyor:

```bash
tools/hostcheck/run_host_tests.sh     # 40 test, 131 kontrol
python3 tools/xrom_preflight.py       # 15 statik kontrol grubu
```

AOSP ağacı ile:

```bash
# .repo/local_manifests/xrom.xml  →  path="vendor/xrom"
repo sync vendor/xrom
source build/envsetup.sh
lunch xrom_x1-trunk_staging-userdebug        # Android 15+
# lunch xrom_x1-userdebug                     # Android 13/14

xrom_preflight --aosp-root "$ANDROID_BUILD_TOP"
m xrom_avfd XVaultPayload xrom_isolation-cpp
m
```

Cihazda:

```bash
tools/xrom_avf_verify.sh              # 8 bölüm, canlı Microdroid VM boot'u dâhil
```

Ayrıntılar: [docs/03 — Bölüm B](docs/03-native-service-and-integration.md#bölüm-b--aosp-ağacına-entegrasyon).

---

## Depo düzeni

Depo, AOSP ağacında `vendor/xrom` konumuna checkout edilir.

```
Android.bp                     Soong config: XROM_AVF_SOURCE_ABI → -DXROM_AVF_ABI
common/                        Host ve misafirin PAYLAŞTIĞI kod — bağımlılıksız
├── crypto/                    SHA-256 (NIST vektörlerine doğrulanmış; guest libcrypto linkleyemiyor)
├── protocol/                  Wire sözleşmesi: çerçeveler, codec, tavanlar
├── vsock/                     Çerçeveli transport (saf POSIX; socketpair ile test edilebilir)
├── recovery/                  Karar katmanı: BCB, hibrit motor, karantina sırası, vault, boot-loop
├── ota/                       update.json + aşamalı doğrulayıcı (kripto bir seam'in arkasında)
└── tests/                     Paylaşılan çekirdeğin host test paketi
device/x1/                     Referans cihaz ağacı (xrom_x1)
├── xrom_board_switches.mk     AVF/pKVM anahtarları — hem BoardConfig hem device.mk bunu okur
├── BoardConfig.mk             GKI, Treble, pKVM cmdline/bootconfig, pvmfw, AVB, sepolicy dizinleri
├── device.mk                  Ürün paketleme
├── avf.mk                     AVF/pKVM ürün yapılandırması (AOSP product_packages.mk keşfi)
├── kernel/                    GKI config fragment + iki kablolama yolu
├── permissions/               AVF feature bildirimi + privapp izin allowlist'i
├── rootdir/                   init.xrom.avf.rc + init.xrom.sentinel.rc (veri dizinleri + servisler)
├── recovery.fstab             Vault ro + recoveryonly; image partition'ı asla rw mount edilmez
├── recovery.mk                Kurtarma/OTA ürün paketleme + derlenmiş recovery policy property'leri
├── vintf/                     Boş ama geçerli manifest/matrix (Treble duruşu)
└── microdroid/xvault/         Microdroid payload: native kütüphane + APK + vm_config.json
sepolicy/
├── system_ext_public/         Dondurulan API: tipler + xrom_avfd_client() makrosu
├── system_ext_private/        allow/neverallow, file/service/property contexts
└── microdroid/                Misafir tarafı: Microdroid imajına derlenir
services/recovery/xrom_sentineld/  Karantina yürütücüsü: BCB, ağ kesme, vault, reboot
services/ota/xrom_ota_installer/   Vault'a yazan TEK binary — sepolicy'de hiç socket'i yok
bootable/xrom_recovery_gate/   Recovery image içinde çalışan karar verici
services/avf/xrom_avfd/        Native C++ daemon
├── VmSpec.*  IsolationPolicy.*        Saf C++17, Android bağımlılığı yok
├── PayloadManifest.*                  Saf: imzalı manifestin yapısal kuralları
├── PayloadVerifier.*                  BoringSSL: imza + ölçüm doğrulaması, trust anchor'lar
├── MicrodroidVmBuilder.*              AVF AIDL tiplerine dokunan TEK dosya
├── AvfController.*  VmLifecycleObserver.*
├── IsolationService.*  DaemonConfig.*  main.cpp
└── tests/                             gtest paketi (cihaz + host)
security/payload_trust/        Payload imza çapaları (genel anahtarlar) + manifest sürüm adımları
security/ota_trust/            OTA imza çapaları — ayrı anahtarlar, ayrı SELinux tipi
aidl/android/xrom/isolation/   AVF daemon'ının dışa açtığı arayüz (dondurulmuş)
aidl/android/xrom/recovery/    IXRecoveryService — ayrı arayüz, ayrı ve çok daha dar çağıran kümesi
tools/
├── xrom_preflight.py          Statik çapraz-kontrol, 29 grup (AOSP gerekmez, --aosp-root ile genişler)
├── xrom_avf_verify.sh         Cihaz üstü doğrulama, 13 bölüm (adb)
├── xrom_sign_payload.py       Payload manifest üretimi + imzalama (openssl CLI)
├── xrom_verify_manifest.py    Aynı kuralların ikinci uygulaması — sürümden önce kontrol
├── xrom_sign_ota.py           update.json + ÇİFT ayrı imza (Ed25519 ve RSA-4096)
├── xrom_verify_ota.py         Cihazdaki aşamalı doğrulamanın host tarafındaki aynası
├── tests/                     İki imzalama hattının uçtan uca testi (34 + 37 iddia)
└── hostcheck/                 Aynı test paketlerini sistem g++ ile çalıştıran shim (4 suite)
docs/                          01 temel · 02 SELinux/izinler · 03 servis · 04 veri düzlemi/imzalama ·
                               05 kendi kendini onaran kurtarma + hibrit OTA
```

---

## Tasarım ilkeleri

Bu depoda tekrar eden birkaç karar var; nedenleri ilgili belgelerde, özetleri burada.

**Sessiz başarısızlık yerine gürültülü başarısızlık.** AVF etkin ama
`product_packages.mk` bulunamıyorsa build durur. `XROM_AVF_SOURCE_ABI`
tanınmıyorsa durur. pKVM arm64 dışında isteniyorsa durur. "AVF'yi açtım"
düşünülen bir cihazın AVF'siz imaj üretmesi, en kötü sonuç olurdu.

**Bilinmeyen şey doğrulanır, varsayılmaz.** Build'in başarılı olması
bayrakların ayarlandığını kanıtlar; cihazın hipervizörle açıldığını kanıtlamaz.
Bu yüzden `gki_xrom_pkvm.fragment` cihaza kuruluyor ve `xrom_avf_verify.sh`
çalışan `/proc/config.gz` ile karşılaştırıyor.

**Tek doğruluk kaynağı.** Kurulum yolları `VmSpec.h`'de bir kez tanımlı;
doğrulayıcı, politika, `file_contexts` ve `tools/xrom_preflight.py` aynı
sabitlerden besleniyor. Servis adı AIDL sabitinden türetiliyor. Union etiketleri
tek makrodan geçiyor. ABI farkı tek bir `#if`'de.

**Fail-closed.** Yapılandırma yüklenemezse daha sıkı varsayılanlar kullanılır.
Bilinmeyen görev sınıfı en kısıtlayıcı sınıfa eşlenir. Debuggable isteği
sessizce düşürülmez, reddedilir. Guest ortamı doğrulanamazsa payload sıfır
olmayan kodla çıkar.

**Yasaklar yazılır.** "Eklemeyi unuttuk" ile "bilerek reddettik" aynı davranışı
üretir ama aynı şey değildir. `/dev/kvm`, `sys_module`, dinleyen vsock, başka
domain'i ptrace'lemek — hepsi açık `neverallow` ile sabitlenmiş durumda.

**Test paketi bir tane.** AOSP gtest'i ve host shim'i **aynı `.cpp`
dosyalarını** derliyor. Kopyalanmış bir test paketi kayan bir test paketidir ve
kayan bir politika testi hiç test olmamasından kötüdür.

**Kodlayıcı ve çözücü aynı kuralları uygular.** Bir tarafın kabul ettiğini öteki
reddediyorsa, hata uzak tarafta bir bozukluk gibi görünür. Bu yüzden
`EncodeTaskBegin` boş `task_id`'yi reddediyor, `ToFixedBuffer` gömülü NUL'u
reddediyor, `EncodeTaskAbort` ve `DecodeTaskAbort` aynı `IsKnownAbortReason()`
fonksiyonunu çağırıyor ve `xrom_preflight.py` her enum değerinin her iki tarafta
da geçtiğini kontrol ediyor.

**Paylaşılan kod bağımlılıksızdır.** `common/` altındaki hiçbir dosya
`android-base`, `libbinder`, `liblog`, `libjsoncpp` veya `libcrypto` içermiyor —
çünkü guest bunları linkleyemiyor (Microdroid payload'a NDK kümesini açıyor).
Bunun karşılığı: veri düzleminin tamamı `socketpair` üzerinde, hipervizörsüz
test edilebiliyor. Yalnızca gerçek bir pVM'e karşı test edilebilen bir transport,
hata yolları hiç çalıştırılmamış bir transport demektir.

**Kriptografi elle yazılmaz.** Uygulanan tek primitif SHA-256 ve o da yayınlanmış
NIST vektörlerine ve `openssl dgst -sha256` çıktısına bayt bayt doğrulanmış
durumda. İmzalar host'ta BoringSSL'de, guest'te AVF'nin attestasyon API'sinde.
SHA-256'nın bile yazılmasının tek sebebi var: guest `libcrypto` linkleyemiyor,
aynı sindirimin birbirinden sapabilen iki uygulaması ise bağımsız tek bir
uygulamadan daha kötü.

**İddia edilen şey kanıtlanan şeydir.** `outputDigest`'i "pVM bunu üretti" diye
sunmak kolay olurdu ve doğru değil. Üç ayrı seviye var, güçleri farklı ve
hangisinin neyi kanıtladığı `AttestationLevel.aidl`'de, `VsockProtocol.h`'de ve
`docs/04` §C.3'te aynı cümlelerle yazılı. Host, guest'in bildirdiği seviyeyi
**düşürebilir, yükseltemez**.

---

## Katkı

```bash
tools/hostcheck/run_host_tests.sh            # 99 test / 456 kontrol
tools/tests/payload_signing_roundtrip.sh     # 34 iddia, openssl gerekir
python3 tools/xrom_preflight.py              # 22 statik kontrol grubu
```

Üçü de AOSP ağacı gerektirmez ve saniyeler sürer. Bir güvenlik politikası
değişikliğini doğrulamak için saatler süren build beklemek gerekmemeli.

Bir payload imzalayacaksanız:

```bash
tools/xrom_sign_payload.py --help            # generate-keys · sign · anchor
tools/xrom_verify_manifest.py --help         # sürümden önce doğrulama
```
