# Oturum 1 — Native C++ servisi, entegrasyon ve doğrulama

## Bölüm A — `xrom_avfd` mimarisi

### A.1 Katmanlar

İstek, hiçbir katmanın bir sonrakini atlayamadığı bir boru hattından geçiyor:

```
 çağıran (uid 1000)
      │  binder: android.xrom.isolation.IXIsolationService/xrom_isolation
      ▼
 IsolationService        AIDL'i düz C++'a çevirir, çağıranı kimliklendirir,
      │                  sıraya alır. Binder thread'i VM boot ETMEZ.
      ▼
 IsolationPolicy         Saf. Karar verir: kabul / red + hangi sınıfta hangi
      │                  tavanlar. Dosya yok, binder yok, saat yok, global yok.
      ▼
 VmSpec                  Saf. Üretilen spec'i doğrular — politikanın kabul
      │                  ettiği niyeti değil, ortaya çıkan artefaktı.
      ▼
 MicrodroidVmBuilder     AVF AIDL tiplerine dokunan TEK dosya.
      │
      ▼
 AvfController           virtualizationservice istemcisi: createOrUpdateIdsigFile,
      │                  allocateInstanceId, createVm, registerCallback, start, stop
      ▼
 VmLifecycleObserver     IVirtualMachineCallback: payload started/ready/finished,
      │                  onError, onDied
      ▼
 crosvm → pKVM (EL2) → pvmfw → Microdroid → microdroid_launcher → libxvault_payload.so
```

Bu ayrımın somut bir karşılığı var: `VmSpec.cpp` ve `IsolationPolicy.cpp`
**hiçbir Android başlığı içermiyor**. Yani AOSP ağacı olmadan, sistem `g++`'ı ile
derlenip test edilebiliyorlar (Bölüm C). Bir katkı verenin politika değişikliğini
doğrulaması için 400 GB checkout ve saatler süren build gerekmiyor.

### A.2 Politika ile doğrulayıcı neden ayrı

İki kapı var ve ikisi de farklı şeye bakıyor:

* `IsolationPolicy::Evaluate()` — **niyet**: bu uid bu görev sınıfını
  isteyebilir mi, bu kadar bellek ayırabilir mi, pKVM var mı, debuggable
  isteyebilir mi?
* `VmSpec::Validate()` — **artefakt**: üretilen VM tanımında yollar izin verilen
  köklerin içinde mi, ad dosya adı olarak güvenli mi, `config_path_in_apk`
  gerçekten `assets/*.json` mi, instance imajı sayfaya hizalı mı?

Biri diğerini çağırmıyor. Test paketi bu ikisinin **anlaştığını** doğruluyor
(`EveryClassGeneratesASpecThatPassesValidation`): politikanın kabul ettiği her
istek, dört görev sınıfı × pKVM var/yok × debuggable var/yok kombinasyonunda
doğrulayıcıdan geçmek zorunda. İkisinin bağımsız olması, birindeki hatanın
diğeri tarafından yakalanması demek.

`Evaluate()` ayrıca **ilk hatada durmaz**: tüm ihlalleri toplar. Tek tek kural
sızıran bir politika, saldırganın yoklayarak öğrenebildiği bir politikadır.

### A.3 Reddetme önceliği

`Rejection` dört değer alıyor ve sıralama sabit:

```
kMalformed (-1)  →  kDenied (-2)  →  kNoHypervisor (-4)  →  kCapacity (-3)
```

Biçim bozuk bir istek bir programlama hatası, politika reddi bir güvenlik
kararı; denetim kaydında ikisinin karışmaması gerekiyor. `kNoHypervisor`
ayrı tutuluyor çünkü orada işle ilgili yanlış bir şey yok — ön koşul ortadan
kalktı (örneğin görev kabul edildikten sonra pKVM kullanılamaz oldu).

### A.4 Kapasite kabul anında rezerve ediliyor

`submitTask()` kapasite kontrolünü ve rezervasyonu **tek kilit altında** yapıyor.
Kontrol edip sonra rezerve etmek, bir istek patlamasının hepsinin kontrolü
geçip hepsinin VM boot etmesine izin verirdi — ki tavan tam olarak bunu
engellemek için var. Rezervasyon görev bittiğinde `ReleaseSlot()` ile
bırakılıyor; iptal yolu dâhil her çıkışta.

### A.5 Binder thread'leri VM boot etmiyor

Bir Microdroid açılışı yüzlerce milisaniye sürer. Bu kadar süre bloke olmuş bir
binder thread'i, izin verilen her çağırana verilmiş bir denial-of-service
koludur. Bu yüzden `submitTask()` yalnızca sıraya alır ve bir sıra numarası
döner; AVF işini `max_concurrent_vms` kadar worker thread yapar.

Callback arayüzü `oneway`. Yavaş ya da takılmış bir istemci daemon'ın worker
thread'ini durduramamalı.

### A.6 `WaitForPayloadLaunched`, `WaitForPayloadReady` değil

Bu, kodu yazarken düzeltilmiş gerçek bir hata sınıfı. `onPayloadReady`, **servis
olarak** çalışan bir payload'ın vsock üzerinde dinlemeye başladığında gönderdiği
sinyal. Bir kez çalışıp çıkan bir payload bunu **hiç göndermez**. Host "ready"
beklerse her X-Vault görevi zaman aşımına düşer.

X-ROM'un ihtiyaç duyduğu şey `onPayloadStarted`: pVM boot etti, pvmfw payload'ı
doğruladı ve `microdroid_launcher` bizim kodumuzu exec'ledi. Gözlemci
`Phase::kPayloadStarted` ve sonrasını kabul ediyor, `kError` ve `kDied`'yi açıkça
hariç tutuyor (enum değerleri sıralamada onların üzerinde olduğu için).

### A.7 Dosya tanımlayıcıları

`MicrodroidVmBuilder::Result` içindeki `VirtualMachineConfig`, açılan tüm fd'lerin
sahibi (`android::os::ParcelFileDescriptor`). Bu sahiplik `createVm()` dönene
kadar sürmek zorunda: `virtualizationservice` tanımlayıcıları `crosvm`'in
tablosuna klonluyor ve bileşik disk imajını `/proc/self/fd/N` yollarıyla
kuruyor. Erken kapatmak, boot edip sonra **kendi partisyonlarını bulamayan** bir
VM üretir.

Tüm açmalar `O_NOFOLLOW | O_CLOEXEC`. `O_NOFOLLOW` sembolik bağ izlemeyi
engelliyor; `IsPathContained()`'ın sözcüksel kontrolü ise `..` bileşenlerini.
İkisi birlikte gerekiyor — tek başına hiçbiri yeterli değil ve kod bunu
söylüyor.

`instance.img` yoksa oluşturuluyor, varsa **yeniden açılıyor**. Silmek, VM'in
türetilmiş sırrına bağlı per-instance durumu yok eder ve payload'ın önceki
açılışta mühürlediği her şeyi geçersiz kılardı. Bu bir yeniden başlatmanın yan
etkisi değil, açık bir operatör eylemi olmalı.

### A.8 Yapılandırma: ne JSON'da, ne özellikte, ne kodda

Üç ayrı mekanizma ve aralarındaki ayrım keyfî değil:

| Mekanizma | İçerik | Neden |
|---|---|---|
| `ro.xrom.avf.*` özellikleri | Değişmez build gerçekleri (`enabled`, `pkvm`, `abi`) | Build yazar, kimse geri okuyup değiştirmez |
| `/system_ext/etc/xrom/avf.json` | Operatör tavanları (eşzamanlılık, bellek bütçesi, izinli uid'ler, zaman aşımları) | Şemalı, sınırlı, tek atomik okuma; her özellik için ayrı SELinux kuralı gerekmiyor |
| Derlenmiş kod (`DefaultOptions`) | Görev sınıfı tablosu | Değiştirmek **imzalı imaj güncellemesi** gerektirmeli, bir config dosyası düzenlemesi değil |

`DaemonConfig::Load()` **fail-closed**: dosya yoksa, 64 KiB'den büyükse, JSON
bozuksa, dizide geçersiz uid varsa ya da bir anahtar yanlış tipte ise → kısmen
uygulanmış bir dosya değil, **fail-safe varsayılanların tamamı**. Fail-safe
değerler JSON'ın isteyebileceği her şeyden daha kısıtlayıcı (debuggable kapalı,
tek VM, 512 MiB), yani yapılandırma yüklenememesi yeteneği azaltır, genişletmez.

Ayrıca JSON'daki her değer derlenmiş bir tavana kırpılıyor. Bu dosya politikayı
yalnızca **sıkılaştırabilir**.

### A.9 Daemon'ın ölmesi VM yetim bırakmaz

`main.cpp` SIGTERM'de kapatma dizisi çalıştırmadan çıkıyor ve bu dikkatsizlik
değil, tasarım: AVF bir VM'i yalnızca bir istemci `IVirtualMachine` binder
tutamacı taşıdığı sürece canlı tutar. Süreç öldüğü anda `virtualizationservice`
başlattığı her VM'i geri alıyor. Sinyal işleyicide daha az iş yapmak daha güvenli
seçenek; yetim pVM temizlenecek bir şey yok.

`Shutdown()` yalnızca normal çıkış yolunda çağrılıyor ve orada da worker'lar
görev ortasında kesilmiyor: `RunTask` her `kWaitPollMs`'de (500 ms) shutdown ve
iptal için yokluyor, yani boşaltma sınırlı.

---

## Bölüm B — AOSP ağacına entegrasyon

### B.1 Depoyu bağlamak

Bu depo AOSP ağacında `vendor/xrom` konumuna checkout edilir. `repo` ile
çalışıyorsanız `.repo/local_manifests/xrom.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<manifest>
  <remote name="xrom" fetch="https://github.com/a23521745-hub/" />
  <project path="vendor/xrom" name="X-ROM" remote="xrom"
           revision="arena/01a0fc80-x-rom" />
</manifest>
```

```bash
repo sync vendor/xrom
```

Depodaki tüm yollar `vendor/xrom/...` köküne göre yazıldı; başka bir konuma
checkout ederseniz `BoardConfig.mk`, `avf.mk` ve `device.mk` içindeki mutlak
yolları güncellemeniz gerekir (preflight bunu yakalar).

### B.2 Lunch ve build

```bash
source build/envsetup.sh

# Android 15+ (trunk-stable)
lunch xrom_x1-trunk_staging-userdebug
# Android 13/14
lunch xrom_x1-userdebug

xrom_preflight --aosp-root "$ANDROID_BUILD_TOP"     # build'den ÖNCE
m xrom_avfd XVaultPayload xrom_isolation-cpp        # hızlı geri bildirim
m                                                     # tam imaj
```

`vendorsetup.sh` iki kabuk fonksiyonu ekliyor: `xrom_preflight` ve
`xrom_verify_device`.

`--aosp-root` ile preflight ek olarak şunları yapar:

* `packages/modules/Virtualization` var mı, `product_packages.mk` hangi yolda
* `virtualizationservice` AIDL dizini hangi düzende (`android/...` mi, eski mi)
* hangi dondurulmuş AIDL sürümleri mevcut
* bu ağaçtaki `VirtualMachineAppConfig` şekli ile `XROM_AVF_SOURCE_ABI` **uyuşuyor mu**
* `system/sepolicy/public/te_macros` içinde `virtualizationservice_use()` var mı
* `system/sepolicy/microdroid/` var mı (misafir politikasının kurulacağı yer)

### B.3 Donanım/yazılım ön koşulları

Build'in sağlayamayacağı tek şey:

1. **Bootloader çekirdeği EL2'de başlatmalı.** EL1'e düşürülmüş bir çekirdekte
   `kvm-arm.mode=protected` sessizce yok sayılır.
2. **Bootloader `androidboot.hypervisor.*` anahtarlarını zaten yazıyorsa**
   `device/x1/xrom_board_switches.mk` içinde
   `XROM_BOARD_SETS_HYPERVISOR_BOOTCONFIG := true` yapın. Aynı bootconfig
   anahtarını iki kez yazmak boot'u bozar.
3. **`pvmfw` partisyonu** yoksa `XROM_TARGET_HAS_PVMFW := false` (aynı dosyada) — ama o zaman
   pVM'lerin doğrulanmış payload'ı ve kalıcı sırrı olmaz; bu yalnızca
   bring-up için kabul edilebilir.
4. **AVB anahtarları.** `BoardConfig.mk` şu an AOSP test anahtarlarını
   kullanıyor. İmza HSM'sindeki cihaz anahtarlarıyla değiştirilmeden hiçbir
   imaj laboratuvar dışına çıkmamalı.

### B.4 Flash ve doğrulama

```bash
adb reboot bootloader
fastboot flashing unlock          # mühendislik cihazında
fastboot -w update out/target/product/x1/*.zip    # veya fastboot flashall
fastboot reboot

# adb root gerektirir
tools/xrom_avf_verify.sh
tools/xrom_avf_verify.sh --no-live-vm     # canlı VM boot etmeden
```

Betik sekiz bölümde doğruluyor ve her satırı PASS/FAIL/WARN/SKIP olarak
işaretliyor:

1. Cihaz kimliği, API düzeyi, root erişilebilirliği
2. **Çekirdek**: `/dev/kvm`, dmesg'de "Protected nVHE mode", cmdline'da
   `kvm-arm.mode=protected`, ve çalışan `/proc/config.gz`'ın cihaza kurulu
   GKI fragment'ı ile karşılaştırılması
3. **Bootconfig**: `androidboot.hypervisor.*` anahtarları ve türetilen
   `ro.boot.*` özellikleri
4. **APEX**: `com.android.virt` mount edilmiş mi, `crosvm` / `virtmgr` / `vm` /
   `microdroid_launcher` içinde mi
5. **Framework**: `android.software.virtualization_framework` özelliği, izinler
6. **SELinux**: enforcing mi, `xrom_avfd` doğru domain'de mi, ikili ve veri
   dizinleri doğru etiketli mi, AVF yığınıyla ilgili denial var mı
7. **X-ROM daemon**: çalışıyor mu, `u:r:xrom_avfd:s0` içinde mi,
   `IXIsolationService` kayıtlı mı, `avf.json` kurulu mu, `ro.xrom.avf.*`
   özellikleri dolu mu
8. **Canlı Microdroid VM**: `/apex/com.android.virt/bin/vm run-microdroid` ile
   gerçekten bir VM boot ediyor, CID alıyor, `vm list`'te görünüyor ve
   durdurulunca CID'yi bırakıyor mu

İkinci bölüm en değerlisi. Build'in başarılı olması bayrakların ayarlandığını
kanıtlar; cihazın hipervizörle açıldığını **kanıtlamaz**.

---

## Bölüm C — Testler

### C.1 Aynı test paketi, iki çalıştırıcı

`services/avf/xrom_avfd/tests/` gerçek test paketi. AOSP içinde:

```bash
atest xrom_avf_core_test
```

AOSP olmadan:

```bash
tools/hostcheck/run_host_tests.sh
# 40 test, 131 kontrol
```

İkincisi, `<gtest/gtest.h>` yerine geçen ~100 satırlık bir shim
(`tools/hostcheck/gtest/gtest.h`) ve ayrı bir `main` kullanarak **aynı `.cpp`
dosyalarını** derliyor. Bilinçli olarak ikinci bir assertion kopyası değil:
kopyalanmış bir test paketi, kayan bir test paketidir ve kayan bir politika testi
hiç test olmamasından kötüdür.

Shim `TEST`, `EXPECT_TRUE/FALSE/EQ/NE/GE`, `ADD_FAILURE` ve `<<` ile bağlam
eklemeyi destekliyor. Fixture, matcher, death test ve parametreli test
desteklemiyor — gerçek paket bunları kullanmaya başlarsa buraya eklenir.

### C.2 Neler test ediliyor

**VmSpec / yol hapsetme**

* Geçerli spec kabul ediliyor
* Ad `xrom_` öneki taşımalı, `[a-z0-9_.-]` dışına çıkamamalı, 64 karakteri
  aşamamalı; `xrom_../../etc/passwd` gibi gezinme dizileri reddedilmeli
* Attestation sınıfı korumasız VM'i reddetmeli, static analysis kabul etmeli
* Debuggable VM yalnızca izin verilmişse
* `os_name` bir allowlist
* Bellek/vCPU sınırları, instance imajının 4096'ya bölünmesi
* Payload APK yalnızca doğrulanmış partisyonundan, değişebilir durum yalnızca
  daemon dizininden
* `config_path_in_apk` yalnızca `assets/*.json`
* **Her sorun rapor ediliyor, sadece ilki değil**
* `ToString()` yolları sızmıyor (logd userdebug'da shell tarafından okunabilir)
* `IsPathContained`: boş, göreli, kökün kendisi, `..` ile dışarı çıkan, `..` ile
  geri dönen, boş bileşen (`//`), boşluk, kontrol karakteri, sonda boşluk, farklı
  kök → hepsi reddediliyor. Kök mutlak ve `/` ile bitmiyorsa **asla** "her şeye
  izin ver"e dönüşmüyor. `payload..v2.idsig` gibi meşru bir ad reddedilmiyor
  (bileşen bazlı karşılaştırma, alt dize araması değil).

**IsolationPolicy**

* İzin verilen istek kabul ediliyor
* Listede olmayan uid reddediliyor (shell, uygulama uid'leri, -1)
* uid 0 user build'de reddediliyor, debuggable build'de kabul ediliyor
* Yapılandırılmış uid listesi gerçekten uygulanıyor
* Yanlış uzunluktaki digest (0/16/31/33/64) → malformed
* task_id karakter kümesi ve uzunluğu → malformed
* **Malformed, denied'dan önce geliyor** ve üç ihlal birlikte rapor ediliyor
* Inbox dışı girdi yolu → denied (gezinen, göreli, dizinin kendisi dâhil)
* pKVM yokken integrity/attestation/crypto → `kNoHypervisor`; static analysis
  yine çalışıyor ve `protected_vm=false` üretiyor
* Debuggable VM hem build hem config istiyor; istek reddediliyor, sessizce
  düşürülmüyor
* Sınıf tavanının üstü → denied, Microdroid tabanının altı → denied, negatif →
  malformed
* Eşzamanlılık tavanı ve bellek bütçesi → `kCapacity`
* **Politikanın kabul ettiği her spec doğrulayıcıdan geçiyor** (4 sınıf × 2 × 2)
* Üretilen adlar görev ve sınıfa göre benzersiz
* Loglar yalnızca debuggable VM için tutuluyor
* Spec asla özel çekirdek istemiyor (`os_name == "microdroid"`,
  `config_path_in_apk == kConfigPathInApk`) — yani `USE_CUSTOM_VIRTUAL_MACHINE`
  fiilen ihtiyaç duyulan izin kümesinin dışında kalıyor

### C.3 Statik kontrol

```bash
python3 tools/xrom_preflight.py
```

Build'in yakalamadığı, çünkü her yarısı tek başına geçerli olan hataları arıyor:

* `VmSpec.h`'deki yol `file_contexts`'teki etiketle uyuşmuyor → daemon'ın kendi
  doğrulayıcısının kabul ettiği dosyayı SELinux reddeder
* Bir `.cpp` ağaçta var ama hiçbir `Android.bp` `srcs`'inde yok → hiç
  derlenmiyor
* `DaemonConfig`'in okuduğu bir anahtar `avf.json`'da yok ya da tersi →
  kimsenin çeviremeyeceği bir düğme
* Microdroid payload config'inde bilinmeyen anahtar → build'de değil, **VM'in
  içinde boot sırasında** hata
* `vm_config.json`'daki `task.command`, `Android.bp`'deki modül adıyla ve APK'nın
  `jni_libs`'iyle uyuşmuyor → `microdroid_launcher` kütüphaneyi bulamaz
* Servis adı AIDL sabiti, `main.cpp` ve `service_contexts` arasında farklı →
  `addService` başarılı olur ve kimse servisi bulamaz
* Bir SELinux tipi kuralda kullanılmış ama bildirilmemiş, ya da bildirilmiş ama
  hiç kullanılmamış
* `.te` dosyasında denge bozuk, `.mk`'da `ifeq`/`endif` eşleşmiyor, `.bp`'de
  süslü parantez açık
* Gerekli en az-ayrıcalık `neverallow`'ları eksik ya da bir `allow` ile geçersiz
  kılınmış
* `kvm-arm.mode` bootconfig'e ya da `androidboot.*` cmdline'a yazılmış
* `avf.mk` her iki `product_packages.mk` konumunu yoklamıyor ya da bulunamazsa
  build'i durdurmuyor
* `xrom_avfd_abi_defaults` daemon'a bağlanmamış → `-DXROM_AVF_ABI` hiç geçilmiyor
  ve `AvfCompat.h` sessizce varsayılanına düşüyor
* Apache-2.0 başlığı eksik (JSON hariç — JSON'da yorum sözdizimi yok)
* AVF anahtarları `BoardConfig.mk`'da doğrudan atanmış ya da `device.mk`
  switches dosyasını include etmiyor → build başarılı olur ama imaj AVF'siz çıkar
  (AOSP, `BoardConfig.mk`'yı ürün yapılandırmasından **sonra** okur)
* `cc_defaults` içindeki `srcs` ile `static_libs` aynı kaynakları iki kez
  derliyor → link'te çift sembol

Linter'ın gerçekten yakaladığı altı sınıfla doğrulandı: daemon'a `/dev/kvm`
vermek, payload yolunu kaydırmak, payload config'ine yabancı anahtar eklemek,
`kvm-arm.mode`'u bootconfig'e taşımak, bir AVF anahtarını `BoardConfig.mk`'da
doğrudan atamak ve `device.mk`'dan switches include'unu kaldırmak.

---

## Bölüm D — Sıradaki oturum için hazır bırakılan yüzeyler

* `common/protocol/VsockProtocol.h` — host↔guest çerçeveleme sözleşmesi
  (magic, sürüm, tip, uzunluk tavanı, 32 bayt digest, 48 baytlık packed
  başlık). Veri düzlemi geldiğinde hem daemon hem payload bunu kullanacak;
  dosya iki tarafın da sahiplenmediği tek yerde duruyor.
* `IsolationTaskResult.outputDigest` — alan tanımlı, şu an boş bırakılıyor.
  AIDL dokümanı, VM içinde hesaplanan özeti daemon'ın dönen baytlar üzerinden
  yeniden hesaplayıp uyuşmazlıkta görevi FAILED yapmasını öngörüyor.
* `sepolicy/microdroid/xrom_microdroid_hardening.te` — `xrom_isolated_payload`
  attribute'u, X-Vault'a adanmış domain geldiğinde miras alınacak şekilde hazır.
* `TaskClass` — dört sınıf tanımlı. Yeni bir sınıf eklemek bir güvenlik kararı:
  `IsolationPolicy::DefaultOptions()`'ta eşleşen bir girdi ve payload tarafında
  karşılığı olmadan preflight bunu yakalamaz, ama `VmSpec::Validate()`
  yakalar (yapılandırılmamış sınıf, doğrulayıcıdan geçemeyen bir spec üretir).
