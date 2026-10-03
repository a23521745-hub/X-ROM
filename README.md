# X-ROM

Android 13+ / AOSP tabanlı, GKI ve Project Treble (GSI) uyumlu, yüksek güvenlikli
bir işletim sistemi. X-Defender (eBPF NDR), X-EyeGuard ve kendi kendini onaran
bütünlük mimarisini, **pKVM** (protected KVM) üzerinde çalışan korumalı
sanal makinelerle birleştiren bir ekosistem.

Lisans: Apache-2.0.

---

## Durum

**Oturum 1 + 2 tamamlandı — temel altyapı ve veri düzlemi.**

Oturum 1 X-ROM'un tüm izolasyon katmanının üzerinde durduğu zemini kurdu: build
ağacında pKVM + AVF etkinleştirme, host ve misafir tarafında SELinux modeli,
izole Microdroid görevleri başlatan native bir C++ servisi. Oturum 2 o VM'in
içine ve dışına akan baytları ekledi: çerçeveli vsock veri düzlemi, payload
imzalama ve çıktının doğrulanması.

| Gereksinim | Nerede | Belge |
|---|---|---|
| pKVM/AVF'yi etkinleştiren `BoardConfig.mk` ve `device.mk` bayrakları | `device/x1/` | [docs/01](docs/01-avf-pkvm-foundation.md) |
| Microdroid için AOSP sistem izinleri ve SELinux yapılandırması | `sepolicy/`, `device/x1/permissions/` | [docs/02](docs/02-selinux-and-permissions.md) |
| İzole Microdroid VM başlatan native C++ servisi | `services/avf/xrom_avfd/` | [docs/03](docs/03-native-service-and-integration.md) |
| Çift yönlü vsock veri düzlemi; payload'ın dış iletişiminin yalnızca bu kanalla sınırlanması | `common/protocol/`, `common/vsock/`, `sepolicy/microdroid/` | [docs/04](docs/04-vsock-data-plane-and-payload-signing.md) §A |
| RSA-4096 / Ed25519 + SHA-256 imza ve ölçüm doğrulaması; imzası doğrulanmayan payload'ın pVM'de çalışmaması | `services/avf/xrom_avfd/PayloadVerifier.*`, `security/payload_trust/`, `tools/xrom_sign_payload.py` | [docs/04](docs/04-vsock-data-plane-and-payload-signing.md) §B |
| `outputDigest` ve dönen verinin doğrulanmış payload tarafından üretildiğinin kanıtlanması | `services/avf/xrom_avfd/IsolationService.cpp`, `aidl/.../IsolationTaskResult.aidl` | [docs/04](docs/04-vsock-data-plane-and-payload-signing.md) §C |

Üçüncü gereksinim hakkında söylenmesi gereken bir şey var ve `docs/04` §C.3'te
uzun uzun yazıldı: çıktıyı doğrulamanın **üç** ayrı gücü var. X-ROM'un gönderdiği
yapılandırma `INSTANCE_BOUND` seviyesine ulaşıyor — host'un sabitlediği
ölçümlerle guest'in VM içinde bağımsız ölçtüğü değerler eşleşiyor ve sonuç
yalnızca o VM instance'ının üretebildiği bir sırla bağlanıyor. Origin'i host'a
kriptografik olarak kanıtlayan `REMOTE_ATTESTED` seviyesi ise RKP, dolayısıyla ağ
erişimi gerektiriyor — yani vsock-only sertleştirme ile aynı anda mümkün değil.
Cihazın erişemediği bir seviyeyi raporlamak, o enum'un hiç olmamasından kötü
olurdu.

Henüz yapılmadı: uzaktan attestasyon, misafir tarafında adanmış SELinux domain'i,
ayrı veri kanalı (`kPortTaskData` ayrılmış ama kullanılmıyor), X-Defender ve
X-EyeGuard entegrasyonu. Kapsam dışı bırakılan her şey ve gerekçesi
`docs/01-avf-pkvm-foundation.md` §8 ve `docs/04` §E'de.

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
└── tests/                     Üçünün de host test paketi
device/x1/                     Referans cihaz ağacı (xrom_x1)
├── xrom_board_switches.mk     AVF/pKVM anahtarları — hem BoardConfig hem device.mk bunu okur
├── BoardConfig.mk             GKI, Treble, pKVM cmdline/bootconfig, pvmfw, AVB, sepolicy dizinleri
├── device.mk                  Ürün paketleme
├── avf.mk                     AVF/pKVM ürün yapılandırması (AOSP product_packages.mk keşfi)
├── kernel/                    GKI config fragment + iki kablolama yolu
├── permissions/               AVF feature bildirimi + privapp izin allowlist'i
├── rootdir/                   init.xrom.avf.rc (veri dizinleri + daemon servisi)
├── vintf/                     Boş ama geçerli manifest/matrix (Treble duruşu)
└── microdroid/xvault/         Microdroid payload: native kütüphane + APK + vm_config.json
sepolicy/
├── system_ext_public/         Dondurulan API: tipler + xrom_avfd_client() makrosu
├── system_ext_private/        allow/neverallow, file/service/property contexts
└── microdroid/                Misafir tarafı: Microdroid imajına derlenir
services/avf/xrom_avfd/        Native C++ daemon
├── VmSpec.*  IsolationPolicy.*        Saf C++17, Android bağımlılığı yok
├── PayloadManifest.*                  Saf: imzalı manifestin yapısal kuralları
├── PayloadVerifier.*                  BoringSSL: imza + ölçüm doğrulaması, trust anchor'lar
├── MicrodroidVmBuilder.*              AVF AIDL tiplerine dokunan TEK dosya
├── AvfController.*  VmLifecycleObserver.*
├── IsolationService.*  DaemonConfig.*  main.cpp
└── tests/                             gtest paketi (cihaz + host)
security/payload_trust/        İmza çapaları (genel anahtarlar) + manifest sürüm adımları
aidl/android/xrom/isolation/   Daemon'ın dışa açtığı arayüz
tools/
├── xrom_preflight.py          Statik çapraz-kontrol, 22 grup (AOSP gerekmez, --aosp-root ile genişler)
├── xrom_avf_verify.sh         Cihaz üstü doğrulama, 12 bölüm (adb)
├── xrom_sign_payload.py       Manifest üretimi + imzalama (openssl CLI)
├── xrom_verify_manifest.py    Aynı kuralların ikinci uygulaması — sürümden önce kontrol
├── tests/                     İmzalama hattının uçtan uca testi (34 iddia)
└── hostcheck/                 Aynı test paketini sistem g++ ile çalıştıran shim
docs/                          01 temel altyapı · 02 SELinux/izinler · 03 servis · 04 veri düzlemi/imzalama
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
