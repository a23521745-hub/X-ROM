# Oturum 1 — Çekirdek ve AVF/pKVM temel altyapısı

Bu belge, X-ROM'un Android Virtualization Framework (AVF) ve protected KVM (pKVM)
üzerine kurduğu izolasyon katmanının **build ağacı tarafını** anlatır: hangi
bayraklar nerede, neden orada, ve yanlış yerleştirildiklerinde ne oluyor.

SELinux ve izin modeli için `02-selinux-and-permissions.md`, native servis ve
entegrasyon adımları için `03-native-service-and-integration.md`.

---

## 1. pKVM nedir ve neden tek bir bayrakla açılmıyor

pKVM, KVM'in EL2'de çalışan bir hypervisor'a dönüştürülmüş hâlidir. Sıradan
KVM'den farkı şudur: normal KVM'de host çekirdeği misafir belleğine istediği
zaman erişebilir; pKVM'de host çekirdeği açılışta kendini EL1'e düşürür ve
stage-2 identity map üzerinden **kendi belleğinin bir kısmına erişimi kaybeder**.
Bir protected VM (pVM) oluşturulduğunda ona bağlanan sayfalar host'un stage-2
haritasından sökülür. Sonuç: Android çekirdeği tamamen ele geçirilmiş olsa bile
pVM'in belleği okunamaz.

Bu, üç ayrı katmanın birlikte doğru olmasıyla gerçekleşir ve hiçbiri tek başına
yeterli değildir:

| Katman | Ne sağlar | X-ROM'da nerede |
|---|---|---|
| `CONFIG_KVM=y` | Çekirdekte KVM var | `device/x1/kernel/gki_xrom_pkvm.fragment` |
| `kvm-arm.mode=protected` | KVM, pKVM olarak açılır | `BOARD_KERNEL_CMDLINE` (BoardConfig.mk) |
| Bootloader'ın çekirdeği **EL2**'de başlatması | Yukarıdaki ikisinin bir anlamı olması | Donanım/yazılım gereksinimi, build ile sağlanamaz |
| `pvmfw` partisyonu | pVM içinde çalışan ilk kod; payload'ı doğrular ve VM sırrını türetir | `BOARD_PVMFWIMAGE_*` (BoardConfig.mk) |
| `androidboot.hypervisor.*` bootconfig | Userspace'in (AVF) cihazın VM çalıştırabildiğini öğrenmesi | `BOARD_BOOTCONFIG` veya bootloader |

En sık yapılan hata son iki satırın yerini karıştırmaktır:

* `kvm-arm.mode=protected` bir **çekirdek parametresidir** → `BOARD_KERNEL_CMDLINE`.
  Bootconfig'e yazılırsa çekirdek onu hiç görmez, KVM normal modda açılır ve
  *hiçbir hata almazsınız*.
* `androidboot.*` anahtarları GKI boot header v4'te **bootconfig**'e taşındı →
  `BOARD_BOOTCONFIG`. Cmdline'a yazılırsa init bunları `ro.boot.*` özelliğine
  dönüştürmez ve AVF "bu cihaz VM desteklemiyor" der.

`tools/xrom_preflight.py` bu iki hatayı statik olarak yakalar;
`tools/xrom_avf_verify.sh` cihazda gerçekten ne olduğunu doğrular.

### pvmfw neden ayrı bir partisyon

pVM'in belleği host'tan korumalı, ama bu koruma bir sorunu çözmüyor: VM'in
sırlarını ilk açılışta ona *kim* verecek? Host veremez — tehdit modeline göre
host'a güvenilmiyor. Cevap pvmfw: hypervisor tarafından korumalı bir bellek
bölgesinden yüklenen, pVM içinde çalışan **ilk** kod. Payload'ı doğrular, per-VM
sırrı türetir ve ancak ondan sonra guest çekirdeğine geçer. Host bunu
engelleyemez, çünkü protected mod açıldığı anda otomatik olarak devreye girer.

Pratik sonuç: `pvmfw` partisyonu olmayan bir cihazda pVM boot eder, ama ne
doğrulanmış bir payload'ı ne de kalıcı bir VM kimliği olur. `BoardConfig.mk`
bunu bir `$(warning)` ile söyler, sessizce geçmez.

---

## 2. GKI ve Treble duruşu

X-ROM'un referans kartı (`device/x1`) bilinçli olarak şu kararları verir:

**Sadece 64-bit.** `TARGET_2ND_ARCH` boş bırakıldı. Gerekçe güvenlik: 32-bit
ABI, hem çekirdekte hem userspace'te ayrı bir saldırı yüzeyi ve ayrıca
denetlenmesi gereken ikinci bir KMI demek. AVF'nin `com.android.virt` APEX'i
zaten yalnızca 64-bit binary içeriyor, yani 32-bit desteği AVF açısından hiçbir
şey kazandırmıyor.

**Boot header v4 + init_boot.** v4, `BOARD_KERNEL_BASE` / `BOARD_KERNEL_OFFSET`
gibi alanları kaldırdı; bu yüzden BoardConfig'te yoklar. Onları yazmak sessizce
yoksayılan değişkenler üretir, ki bu "ayarladım ama etkisi olmadı" sınıfından bir
hatadır.

**AVB flags = 0.** `BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS += --flags 0`. Yaygın
kopyala-yapıştır `--flags 3`'tür (verification + hashtree kapalı) ve bir güvenlik
işletim sisteminde bunun bulunması, diğer her şeyin anlamını iptal eder.
Mühendislik cihazlarında kilit açıkken `fastboot --disable-verity
--disable-verification` kullanılır; imajın kendisi değiştirilmez.

**VINTF bilinçli olarak boş.** `device/x1/vintf/manifest.xml` ve
`compatibility_matrix.xml` boş, çünkü x1'in vendor HAL'i yok ve AVF **vendor
tarafında değil platform tarafında** yaşıyor. Bu bir eksik değil, Treble
duruşunun kendisi: bu vendor imajının üzerine jenerik bir system imajı
flash'landığında X-ROM'un eklediği her şey çalışmaya devam eder.
`PRODUCT_ENFORCE_VINTF_MANIFEST := true` ile, ileride bir vendor bileşeni
framework arayüzü isterse ve bildirmezse bu bir build hatası olur.

**Vendor SELinux dizini bilinçli olarak yok.** `/dev/kvm` (`kvm_device`),
`/sys/firmware/devicetree/base/avf` (`sysfs_dt_avf`) ve `ro.boot.hypervisor.*`
(`hypervisor_prop`) AOSP tarafından zaten etiketleniyor. Kural içermeyen bir
`BOARD_SEPOLICY_DIRS` girdisi yalnızca vendor yüzeyini genişletirdi.

---

## 3. AVF'nin ürün yapılandırması: neden iki yol deneniyor

AVF'yi bir ürüne eklemenin doğru yolu, AOSP'nin kendi makefile'ını
devralmaktır:

```make
$(call inherit-product, packages/modules/Virtualization/build/apex/product_packages.mk)
```

Bu tek satır `com.android.virt` APEX'ini (virtualizationservice, virtmgr,
crosvm, Microdroid imajları, pvmfw, `vm` CLI) ve `com.android.compos`'u
(izole derleme servisi) getirir; ayrıca AVF'nin ihtiyaç duyduğu
`PRODUCT_SYSTEM_FSVERITY_GENERATE_METADATA` ve izole derleme özelliklerini
ayarlar.

Sorun şu ki bu dosyanın yolu sürümler arasında taşındı — Virtualization modülü
`android/ build/ microdroid/` üst dizinlerine yeniden organize edildi:

| Sürüm | Yol |
|---|---|
| Android 13 / 14 | `packages/modules/Virtualization/apex/product_packages.mk` |
| Android 15 ve sonrası | `packages/modules/Virtualization/build/apex/product_packages.mk` |

`device/x1/avf.mk` ikisini de `$(wildcard ...)` ile yoklar, bulunanı devralır ve
**hiçbiri yoksa build'i durdurur**. Sessizce AVF'siz bir imaj üretmek,
"AVF'yi açtım" diye düşünülen bir cihazda en kötü sonuç olurdu.

---

## 4. AVF AIDL'inin sürüm farkı ve `XROM_AVF_SOURCE_ABI`

Native servisin derlenebilmesi için bilmesi gereken tek şey, hangi AVF AIDL
şekline karşı derlendiği. İki gerçek fark var:

**`createVm()` imzası**

```
Android 13     createVm(config, consoleFd, osLogFd)                     3 argüman
Android 14+    createVm(config, consoleOutFd, consoleInFd, osLogFd)     4 argüman
```

**`VirtualMachineAppConfig` şekli**

```
Android 13     düz parcelable: configPath, debugLevel (NONE/APP_ONLY/FULL),
               protectedVm, memoryMib, numCpus, cpuAffinity, taskProfiles

Android 14+    name (utf16), instanceId (byte[64]), osName (utf8),
               iç içe Payload union'ı (configPath | payloadConfig),
               numCpus yerine cpuTopology, debugLevel (NONE/FULL)
```

Not: `startVirtualMachine()` diye bir metot **yok**; AVF'nin istikrarlı akışı
Android 13'ten günümüze `createVm()` + `IVirtualMachine.start()`'tır. Bu,
dokümantasyonda sık karşılaşılan bir karışıklık ve X-ROM'un kodu doğrudan AOSP
kaynağından doğrulanmış imzalara göre yazıldı.

Bu fark tek bir değişkenden yönetiliyor:

```make
XROM_AVF_SOURCE_ABI ?= ANDROID_14_PLUS     # veya ANDROID_13
```

### Değişken neden `BoardConfig.mk`'da değil

AOSP ürün yapılandırmasını `BoardConfig.mk`'dan **önce** okur:
`build/make/core/envsetup.mk` önce `product_config.mk`'yı (dolayısıyla
`xrom_x1.mk → device.mk → avf.mk`) sonra `BoardConfig.mk`'yı include eder. Yani
`BoardConfig.mk`'da atanan bir değişken `avf.mk` için **görünmez**.

Bu, AVF'de sessizce kaybolan bir hataya yol açar: `avf.mk` `XROM_ENABLE_AVF`'yi
boş görür, hiçbir şey devralmaz, Soong config'i ayarlamaz — ve build
**başarıyla** AVF'siz bir imaj üretir. Bu yüzden beş anahtar
`device/x1/xrom_board_switches.mk` içinde `?=` ile tanımlı ve iki taraf da aynı
dosyayı include ediyor. `tools/xrom_preflight.py` hem include'ların varlığını hem
de hiçbir tarafın bu değişkenleri doğrudan atamadığını kontrol ediyor.

```
xrom_board_switches.mk      XROM_ENABLE_AVF, XROM_ENABLE_PKVM,
        │                   XROM_AVF_SOURCE_ABI, XROM_TARGET_HAS_PVMFW,
        │                   XROM_BOARD_SETS_HYPERVISOR_BOOTCONFIG
        ├── BoardConfig.mk  cmdline, bootconfig, pvmfw, partisyonlar, sepolicy dizinleri
        └── device.mk → avf.mk   PRODUCT_PACKAGES, özellikler, soong_config_set
```

Zincir şöyle işliyor:

```
xrom_board_switches.mk   XROM_AVF_SOURCE_ABI ?= ANDROID_14_PLUS
      │   (hem BoardConfig.mk hem device.mk bunu include eder)
      │
avf.mk           $(call soong_config_set,xrom,avf_abi,$(XROM_AVF_SOURCE_ABI))
      │
Android.bp       soong_config_module_type "xrom_avf_cc_defaults"
                 → xrom_avfd_abi_defaults → cflags: ["-DXROM_AVF_ABI=14"]
      │
AvfCompat.h      #if XROM_AVF_ABI >= 14  (tek yer)
      │
MicrodroidVmBuilder.cpp / AvfController.cpp
```

AIDL kütüphanesi **sürüm numarası olmadan** bağlanıyor
(`android.system.virtualizationservice-cpp`), çünkü Soong bu adı ağaçtaki en yeni
dondurulmuş sürüme çözer; böylece tek bir X-ROM ağacı Android 13'ten güncele
kadar düzenleme gerektirmeden derlenir. Vendor ABI'sini dondurmak gerektiğinde
`-V4-cpp` gibi açık bir sürüm yazılır; mevcut sürümler
`packages/modules/Virtualization/aidl_api/android.system.virtualizationservice/`
altındaki dizinlerdir.

### Üçüncü fark: AIDL C++ union etiketleri

AIDL'in resmî "backends" dokümanı union etiketlerini `Foo::intField` olarak
gösteriyor; güncel aidl üreticisi ise `Foo::Tag::kIntField` üretiyor. İkisi de
derleme zamanında bağdaşmaz, yani yanlış tahmin "sessizce yanlış alan" değil
"derleme hatası" üretir — ama yine de tek satırlık bir anahtar olması daha iyi.
Tüm union erişimleri `AvfCompat.h`'daki `XROM_UNION_TAG` makrosundan geçiyor:

```c
// Ağacınız enum-class şekli üretiyorsa Android.bp'ye ekleyin:
cflags: ["-DXROM_AIDL_UNION_TAG_ENUM_CLASS"],
```

---

## 5. Microdroid payload paketleme

X-Vault payload'ı AOSP'nin Microdroid sözleşmesini birebir izler:

1. `cc_library_shared` → `libxvault_payload`, `AVmPayload_main` sembolünü verir,
   `sdk_version: "current"` (misafir kodu NDK alt kümesine karşı derlenir).
2. `android_app` → `XVaultPayload`, `jni_libs: ["libxvault_payload"]` ve
   `use_embedded_native_libs: true`. İkincisi önemli: `.so` APK içinde
   sıkıştırılmamış ve sayfaya hizalı durur, böylece Microdroid onu yazılabilir
   bir alana çıkarmak yerine doğrudan **doğrulanmış APK'dan** map'leyebilir.
3. VM yapılandırması `assets/vm_config.json` olarak APK'ya gömülür ve host
   tarafında `configPath = "assets/vm_config.json"` olarak geçirilir — başında
   `/` **yok**, çünkü bu bir dosya sistemi yolu değil APK içi yoldur.

`vm_config.json` içinde yorum anahtarı olamaz. Microdroid bu dosyayı
`config_schema.xsd`'ye karşı **VM'in içinde** doğrular; bilinmeyen bir anahtar
uyarı değil, açılış hatasıdır. Bu yüzden açıklamalar bu belgede ve
`device/x1/microdroid/xvault/README.md`'de, dosyada değil.

`configPath` biçimi AIDL'e göre `USE_CUSTOM_VIRTUAL_MACHINE` izni gerektirir.
`xrom_avfd` uid `system` (1000) altında çalıştığı için bu izin
PermissionManagerService tarafından zaten verilir; ayrıntı
`02-selinux-and-permissions.md`'de.

---

## 6. Çekirdek yapılandırma parçası (fragment)

`device/x1/kernel/gki_xrom_pkvm.fragment` iki amaçlı:

* **ACK'den derliyorsanız** girdi: `kernel_build`'ın `defconfig_fragments`
  özelliğiyle `gki_defconfig` üzerine birleştirilir.
* **Hazır GKI kullanıyorsanız** sözleşme: cihaza
  `/system_ext/etc/xrom/kernel/gki_xrom_pkvm.fragment` olarak kurulur ve
  `tools/xrom_avf_verify.sh` çalışan çekirdeğin `/proc/config.gz`'ını onunla
  karşılaştırır.

İkinci kullanım, ilk bakışta gereksiz görünüyor çünkü Google'ın GKI'si bugün
`CONFIG_KVM=y` ve listedeki tüm sertleştirme sembollerini zaten içeriyor. Değeri
bugün değil yarın: gelecekteki bir GKI örneğin `CONFIG_ARM64_MTE`'yi düşürürse
bu, sessizce zayıflamış bir X-ROM değil, kırmızı bir CI işi olur.

Fragment'ta `[gki-default]` olarak işaretlenmiş satırlar GKI'nın zaten
ayarladığı değerler. Bilerek tekrar yazıldılar: niyeti belgeliyorlar ve
yukarıdaki drift kontrolünü mümkün kılıyorlar.

Ayrıca fragment, **açıkça reddedilen** seçenekleri de listeliyor
(`CONFIG_DEVMEM`, `CONFIG_KPROBES`, `CONFIG_USERFAULTFD`, `CONFIG_BPF_SYSCALL`).
Bir güvenlik yapılandırmasında "ne açtık" kadar "neyi bilerek kapattık" da
kayda değer; `BPF_SYSCALL` notu özellikle önemli çünkü X-Defender bir eBPF NDR
ve o oturum kendi imza-yükleme izin listesiyle birlikte gelecek.

---

## 7. Bu oturumda alınan kararlar

| Karar | Gerekçe | Alternatifi neden reddedildi |
|---|---|---|
| Tüm X-ROM kodu `vendor/xrom` altında tek depo | Tek `repo` girdisi, tek inceleme yüzeyi | `device/xrom` + `vendor/xrom` iki depo: tek repodan iki yola eşlenemez |
| Referans cihaz `vendor/xrom/device/x1` | AOSP cihaz ağaçlarının `device/` altında olmasını gerektirmez | Kök dizinde `device/` ve `vendor/` karışımı |
| AVF ürün paketi `$(wildcard)` ile keşfediliyor | Android 13→güncel tek ağaç | Yolu sabitlemek: her rebase'de kırılır |
| AIDL kütüphanesi sürümsüz bağlanıyor | Tek ağaç, her sürümde derlenir | Sürüm sabitlemek: eski ağaçta modül bulunamaz |
| ABI farkı Soong config değişkeniyle | Makefile kararı derleyiciye ulaşır | El yordamıyla `-D` eklemek: unutulur |
| AVF anahtarları ayrı bir switches dosyasında | AOSP BoardConfig'i ürün yapılandırmasından sonra okur; orada tanımlansalardı `avf.mk` hiç görmezdi | `BoardConfig.mk`'da tanım: build başarılı, imaj AVF'siz |
| Union etiketleri tek makroda | Derleme hatası tek satırlık düzeltme | Doğrudan yazmak: revizyon farkında her çağrı yeri değişir |
| Sadece 64-bit | Saldırı yüzeyi ve KMI yarıya iner | 32-bit: AVF'ye hiçbir katkı sağlamaz |
| AVB `--flags 0` | Doğrulama açık | `--flags 3`: diğer her garantinin anlamını iptal eder |
| Boş VINTF, boş vendor sepolicy | Gerçekten kural yok | Boş iskelet: genişlemiş yüzey, sahte güven |
| `debuggable` VM isteği reddedilir, sessizce düşürülmez | Çağıran, log/shell gelmeyeceğini bilir | Sessiz düşürme: hata ayıklanamayan oturum |
| Host `WaitForPayloadLaunched` bekler, `Ready` değil | Run-once payload'lar `onPayloadReady` göndermez | `Ready` beklemek: her X-Vault görevi zaman aşımına düşer |

---

## 8. Bu oturumda yapılmayanlar

Bilinçli kapsam dışı bırakılanlar ve neden:

* **vsock veri düzlemi.** `common/protocol/VsockProtocol.h` çerçeveleme
  sözleşmesini tanımlıyor (magic, sürüm, uzunluk tavanı, digest), ama host ile
  misafir arasındaki gerçek aktarım bağlanmadı. Bu yüzden `SUCCEEDED` şu an
  "izole payload çalıştı ve 0 ile çıktı" demek, "çıktısı doğrulandı" demek
  **değil**. Bu ayrım `IsolationService.cpp` içinde ve AIDL dokümanında açıkça
  yazılı.
* **Payload imzalama ve misafir tarafında adanmış SELinux domain'i.** Şu an
  X-Vault, AOSP'nin hazır `microdroid_payload` domain'inde çalışıyor. Adanmış
  domain, misafir içi `mac_permissions.xml` + `seapp_contexts` gerektirir;
  yarım yapıldığında geçiş yapmayan bir domain üretir.
  `sepolicy/microdroid/xrom_microdroid_hardening.te` bunun yerine tüm Microdroid
  payload'larına uygulanan bir `attribute` üzerinden sertleştirme yapıyor.
* **Erken VM (early VM), cihaz atama (VFIO), VM ağı.** Hepsi ayrı AVF release
  bayrakları ve ayrı tehdit modelleri gerektiriyor.
* **X-Defender ve X-EyeGuard entegrasyonu.** Bu oturum yalnızca onların
  üzerinde koşacağı izolasyon zeminini kuruyor.
