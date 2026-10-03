# Oturum 1 — SELinux modeli ve sistem izinleri

Microdroid'in izole güvenlik görevleri çalıştırabilmesi için iki ayrı politika
katmanı gerekiyor. İkisini karıştırmak bu konudaki en yaygın hata:

* **Host tarafı** — Android'in kendisi. `xrom_avfd`'nin AVF'ye ulaşabilmesi, ama
  `/dev/kvm`'e, başka süreçlere ve kendi VM durumuna kimsenin ulaşamaması.
* **Misafir tarafı** — Microdroid'in içi. pVM'in içinde çalışan payload'ın
  sınırlanması. Bu politika Android imajında değil, **Microdroid imajının
  içinde** derlenir.

---

## 1. Host tarafı: Treble katmanlaması

X-ROM'un sepolicy'si üç dizine ayrıldı ve bu ayrım dekoratif değil — Treble'ın
donma kurallarını izliyor:

```
sepolicy/
├── system_ext_public/       platform politika API'si (dondurulur)
│   ├── xrom_avfd.te         type xrom_avfd, type xrom_avfd_exec
│   │                        + xrom_avfd_client(domain) m4 makrosu
│   └── service.te           type xrom_avf_service
├── system_ext_private/      uygulama ayrıntısı (her build değişebilir)
│   ├── xrom_avfd.te         allow / neverallow kuralları
│   ├── file.te              veri, payload, yapılandırma dosya tipleri
│   ├── property.te          xrom_avf_prop
│   ├── file_contexts        yol → etiket
│   ├── service_contexts     binder adı → etiket
│   └── property_contexts    özellik adı → etiket
└── microdroid/              misafir tarafı (Microdroid imajına derlenir)
    └── xrom_microdroid_hardening.te
```

Kural: **public'te yalnızca tip bildirimi ve makro, private'ta her şey.**
Vendor/product politikasının görebileceği tek şey public; oraya bir `allow`
koyduğunuzda onu bir daha geri alamazsınız.

Bu iki dizin `BoardConfig.mk`'dan bağlanıyor:

```make
SYSTEM_EXT_PUBLIC_SEPOLICY_DIRS  += vendor/xrom/sepolicy/system_ext_public
SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += vendor/xrom/sepolicy/system_ext_private
```

`BOARD_SEPOLICY_DIRS` **bilerek tanımlı değil**: vendor tarafında kural
gerektiren bir şey yok (`01-avf-pkvm-foundation.md` §2).

---

## 2. AVF istemcisi olmanın doğru yolu: `virtualizationservice_use()`

`xrom_avfd`'nin AVF'ye erişimini AOSP'nin kendi makrosu veriyor:

```
virtualizationservice_use(xrom_avfd)
```

Bunu elle yazılmış kurallara tercih etmenin nedeni somut: bu makro **Android 15'te
anlam değiştirdi.**

| Sürüm | Makronun yaptığı |
|---|---|
| Android 13/14 | `virtualization_service`'i bul, `virtualizationservice` ile iki yönlü `binder_call`, `virtualizationservice` + `crosvm` ile fd/fifo paylaşımı, sahip olunan VM'in vsock'una okuma/yazma, `hypervisor_prop` okuma |
| Android 15+ | Aynı şekil, ama istemci artık uzun ömürlü servise bağlanmak yerine `virtmgr` / `virtualizationmanager`'ı **exec ediyor** ve onunla bir unix socket üzerinden konuşuyor |

Bir revizyonun kurallarını kopyalayan bir politika, diğeriyle derlenmez ya da —
daha kötüsü — derlenir ve çalışmaz. Makroyu kullanmak bu geçişi X-ROM için
bedava hâle getiriyor.

Bu yüzden politika, sürümler arasında var olmayan tiplere de **bilerek**
dokunmuyor: `virtualizationmanager`, `sysfs_dt_avf`, `vfio_handler`
Android 14/15/16'da ortaya çıktı; Android 13 tabanında derleme hatası
verirlerdi. Dosyanın başındaki portabilite notu bunu belgeliyor.

---

## 3. En az yetki: verilenler ve verilmeyenler

### Verilenler (her biri kullanılan bir yetenek)

| Kural | Neden gerekli |
|---|---|
| `init_daemon_domain(xrom_avfd)` | init'in exec'te domain geçişi yapması |
| `binder_use` + `add_service(xrom_avfd, xrom_avf_service)` | Kendi arayüzünü yayınlamak |
| `virtualizationservice_use(xrom_avfd)` | AVF istemcisi olmak |
| `xrom_avfd_data_file:dir/file create_*` | `/data/misc/xrom/avf` altında instance id, `.idsig`, `instance.img`, VM logları |
| `xrom_vault_payload_file:dir/file r_*` | Payload APK'yı okumak |
| `xrom_avfd_config_file:dir/file r_*` | `avf.json`'ı okumak |
| `get_prop(hypervisor_prop)` | Hipervizör yeteneklerini okumak |
| `set_prop(xrom_avfd, xrom_avf_prop)` + `set_prop(init, xrom_avf_prop)` | Çalışma zamanı durumu ve build.prop'tan yüklenen `ro.xrom.avf.*` |
| `self:capability sys_resource` | `RLIMIT_MEMLOCK` yükseltmek — VM belleği ve sayfa tabloları kilitlenebilsin |
| `r_dir_file(proc_meminfo)` | VM'leri tahminle değil gerçek boş belleğe göre boyutlandırmak |

### Verilmeyenler — ve bunlar birer `neverallow` ile sabitlendi

Bir güvenlik politikasında "eklemeyi unuttuk" ile "bilerek reddettik" aynı
davranışı üretir ama aynı şey değildir. İkincisini zorunlu kılmak için:

```
neverallow xrom_avfd kvm_device:chr_file *;
```
`/dev/kvm` yalnızca `crosvm`'indir. Daemon onu açabilseydi, daemon'daki bir hata
bir **hypervisor-escape** aracına dönüşürdü ve VMM'i kendi domain'ine hapsetmenin
bütün anlamı kaybolurdu.

```
neverallow xrom_avfd self:capability { sys_module sys_rawio sys_admin sys_ptrace
                                       sys_boot dac_override dac_read_search };
neverallow xrom_avfd self:capability2 { mac_admin mac_override syslog };
```
İşi bir VMM'e dosya tanımlayıcısı vermek olan bir sürecin çekirdek modülü
yüklemesi, fiziksel belleğe dokunması, mount yapması veya DAC'ı atlaması için
hiçbir neden yok.

```
neverallow xrom_avfd { domain -init -xrom_avfd }:process ptrace;
```
Kendi başlatmadığı hiçbir şeyi izleyemez. VM süreçleri `crosvm`'in çocukları.

```
neverallow xrom_avfd self:vsock_socket { create bind listen accept };
```
Daemon bir vsock **istemcisi**. Payload'lara, `virtualizationservice`'in
oluşturup fd olarak devrettiği soketlerle ulaşır. Kendi dinleyen soketini
açabilmesi, cihazdaki her VM'e giden ikinci ve denetlenmemiş bir kanal demek
olurdu.

```
neverallow { domain -xrom_avfd -init } xrom_avfd_data_file:file { open create write append };
```
Bu, AOSP'nin kendi `virtualizationservice_data_file`'ından **daha sıkı**: orada
crashdump için başka domain'ler okuyabiliyor. X-ROM'un VM durumu payload
çıktısı içerebilir, o yüzden kimse açamıyor. `virtualizationservice` ve `crosvm`
bu dosyalara yalnızca **devraldıkları fd üzerinden** erişiyor — kuralda `read`
var, `open` yok. AOSP'nin `crosvm.te`'deki değişmezi birebir aynı:

```
allow { virtualizationservice crosvm } xrom_avfd_data_file:file { getattr read write ioctl lock };
```

```
neverallow { domain -init } xrom_vault_payload_file:file { write append setattr };
```
Payload dizini **ölçülen** bir artefakt. APK'nın fs-verity özeti pvmfw tarafından
VM kimliğine ölçülüyor; çalışma zamanında yazılabilir bir payload yolu, ele
geçirilmiş bir host'un *orijinali gibi attestasyon yapan* bir VM boot etmesine
izin verirdi.

```
neverallow { domain -xrom_avfd -init } xrom_avf_service:service_manager add;
neverallow { appdomain -priv_app -system_app } xrom_avf_service:service_manager find;
```
Kimse servis adını taklit edemez ve uygulamalar adı çözemez. Erişim domain bazında
`xrom_avfd_client()` ile veriliyor; ayrıcalıklı ve sistem uygulamaları bilinçli
istisna, çünkü `xrom_avf_privapp_permissions.xml` tam olarak onlar için var.

```
neverallow { domain -init -xrom_avfd } xrom_avf_prop:property_service set;
```
AOSP'nin `virtualizationservice_prop` için kullandığı kalıbın aynısı: tip başına
açık neverallow.

---

## 4. Etiketler ve yollar

`file_contexts` ile `services/avf/xrom_avfd/VmSpec.h` **aynı yolları** söylemek
zorunda, yoksa daemon'ın kendi doğrulayıcısının kabul ettiği bir dosyayı SELinux
reddeder. Bu iki dosyanın ayrılmasını engellemek için yollar tek yerde
tanımlı (`VmSpec.h`) ve `tools/xrom_preflight.py` bunları `file_contexts`,
`init.xrom.avf.rc`'deki `mkdir` satırları ve modlara karşı çapraz kontrol ediyor.

| Yol | Etiket | Mod | Not |
|---|---|---|---|
| `/system_ext/bin/xrom_avfd` | `xrom_avfd_exec` | — | `init_daemon_domain` bu etiketi eşleştirir; eşleşmezse daemon **init domain'inde** çalışır |
| `/data/misc/xrom/avf` | `xrom_avfd_data_file` | 0700 | Per-VM durum |
| `/data/misc/xrom/inbox` | `xrom_avfd_data_file` | 0770 | Görev girdisi; politika her isteği buraya hapseder |
| `/system_ext/app/XVaultPayload` | `xrom_vault_payload_file` | — | Payload APK |
| `/system_ext/etc/xrom/avf.json` | `xrom_avfd_config_file` | — | Daemon yapılandırması |
| `/system_ext/etc/xrom/kernel/gki_xrom_pkvm.fragment` | (AOSP `system_file`) | — | Cihaz üstü doğrulama için |

`init.xrom.avf.rc`'de `seclabel` **yok**: domain geçişi ikili dosyanın
`file_contexts` etiketinden türetiliyor. Sabit yazılmış bir `seclabel`, ikili
taşındığında çalışmaya devam eder ama yanlış domain'de çalışır — yani sessizce
yanlış olur.

Özellikler:

```
ro.xrom.avf.       u:object_r:xrom_avf_prop:s0     # build gerçeği
xrom.avf.          u:object_r:xrom_avf_prop:s0     # çalışma zamanı durumu
persist.xrom.avf.  u:object_r:xrom_avf_prop:s0     # operatör override'ı
```

`xrom_avf_prop` düz `property_type` olarak bildirildi, `system_internal_prop()`
makrosuyla değil: o makro `system/sepolicy/private/property.te` içinde ve
davranışı sürümler arasında değişti. X-ROM'un politikası Android 13'ten güncele
kadar **değişmeden** derlenmek zorunda.

Servis adı üç yerde aynı olmak zorunda ve preflight bunu kontrol ediyor:

```
aidl     const String INSTANCE = "xrom_isolation";
main.cpp kServiceName = "android.xrom.isolation.IXIsolationService/xrom_isolation";
contexts android.xrom.isolation.IXIsolationService/xrom_isolation u:object_r:xrom_avf_service:s0
```

Kararlı AIDL servisleri `<arayüz>/<örnek>` biçiminde kaydedilir ve
servicemanager'ın eşleştirdiği dize tam olarak budur.

---

## 5. İzinler: AVF'yi kim, neyle çağırabiliyor

`virtualizationservice` yalnızca SELinux'a güvenmez; çağıran UID'nin ilgili
kısıtlı izni taşıyıp taşımadığını PermissionManagerService'e sorar.

| İzin | Koruma düzeyi | Ne için |
|---|---|---|
| `android.permission.MANAGE_VIRTUAL_MACHINE` | `signature\|privileged` | App config ile VM oluştur/başlat/durdur/sorgula. API 34'te geldi; Android 14'te yalnızca ayrıcalıklı uygulamalara, Android 15'ten itibaren tüm ön-yüklü uygulamalara verilebiliyor |
| `android.permission.USE_CUSTOM_VIRTUAL_MACHINE` | `signature\|privileged` | `VirtualMachineRawConfig`, özel guest çekirdeği, cihaz atama **ve X-ROM'un kullandığı `configPath` biçimi** |
| `android.permission.MANAGE_VIRTUALIZATION_STATE` | `signature\|privileged` | Küresel sanallaştırma durumunu ayarlamak (ör. termal baskıda tüm VM'leri askıya almak) |

### `xrom_avfd` neden bu listede yok

Çünkü uid `system` (AID 1000) altında çalışıyor ve PermissionManagerService
uid 0 ile uid 1000'e **tüm** izinleri verir. Yani allowlist girdisi ölü metin
olurdu; daemon'ın izolasyonu SELinux'tan geliyor, izinlerden değil. Bu, yukarıdaki
`neverallow` listesinin neden bu kadar uzun olduğunu da açıklıyor: uid üzerinden
yetki aldıysanız, sınırlamanın başka bir yerde gerçekten uygulanıyor olması gerekir.

`init.xrom.avf.rc`'deki `user system` satırı bu yüzden bir ayrıntı değil, izin
modelinin kendisi.

### `xrom_avf_privapp_permissions.xml`

Bu dosya **ileriye dönük**: Oturum 1'de ayrıcalıklı bir host uygulaması yok.
Şimdiden kuruluyor ki izin yolu hazır ve **zorlanan** durumda olsun
(`ro.control_privapp_permissions=enforce` — cihaz, allowlist'te karşılığı olmayan
bir `signature|privileged` izin isteyen ayrıcalıklı uygulamayla boot etmez).
X-Vault host uygulaması geldiğinde dosyadaki paket adı gerçek `applicationId` ile
eşleştirilecek.

Kurulu olmayan bir paket için allowlist girdisi zararsızdır; ama ayrıcalıklı bir
uygulamanın eşleşen girdi olmadan bu izinleri istemesi **boot zamanı reddidir**.

### Neden `configPath` ve neye mal oluyor

`payloadConfig` (açık parametre yapısı) yerine APK içindeki JSON'ı seçmenin
bedeli `USE_CUSTOM_VIRTUAL_MACHINE`. Karşılığında alınan şey ölçülebilirlik:
APK içindeki JSON imzalı ve fs-verity kapsamlı, dolayısıyla **pvmfw'ın VM
kimliğine ölçtüğü şeyin parçası**. Host'tan geçen ad-hoc bir parametre yapısı
değil. Bir güvenlik ürününde ölçülen yapılandırma, gereksinimi daha geniş olan
izne tercih edilir.

---

## 6. Misafir tarafı: Microdroid politikası

`sepolicy/microdroid/xrom_microdroid_hardening.te` Android'e değil, **pVM'in
içindeki** Microdroid'e uygulanır.

### Nereye kuruluyor

Microdroid'in politikası `system/sepolicy/microdroid/` altından derlenir ve
oraya hiçbir `BOARD_*` / `SYSTEM_EXT_*` değişkeniyle ulaşılamaz — cihazın
politika derlemesinin değil, Microdroid imajının parçasıdır. X-ROM AOSP'yi
kaynaktan derlediği için dosya, X-ROM yama serisiyle şuraya kurulur:

```
system/sepolicy/microdroid/system/private/xrom_microdroid_hardening.te
```

**Başka bir yere konursa sessizce derlenmez** ve VM hazır Microdroid
politikasıyla çalışır. `tools/xrom_preflight.py` dosyanın yerini kontrol ediyor.

### Neden yeni bir domain değil, bir attribute

Microdroid, payload'ın domain'ini payload APK'sının `seinfo`'sundan seçer; o da
misafir içindeki `mac_permissions`'tan gelir. X-Vault'a özel bir domain vermek
demek, misafir tarafında X-ROM payload imza sertifikasına bağlı bir
`mac_permissions.xml` **ve** `seapp_contexts` göndermek demek. Doğru nihai durum
bu ve payload imzalama oturumunda yapılacak; şimdi yarım yapmak, içine hiçbir
şeyin geçiş yapmadığı bir domain üretirdi.

Bunun yerine X-ROM, cihazındaki **her** Microdroid payload'ı için geçerli olan
bir iddiada bulunuyor — çünkü X-ROM'da Microdroid'i başka bir amaçla boot eden
hiçbir şey yok (Terminal uygulaması yok, Linux geliştirme ortamı yok, üçüncü
taraf payload yolu yok):

```
attribute xrom_isolated_payload;
typeattribute microdroid_payload xrom_isolated_payload;
```

Böylece `neverallow`'lar boş bir attribute üzerinde değil, gerçekten çalışan bir
şey üzerinde duruyor ve gelecekteki adanmış domain miras alacak bir şeye sahip.

### Misafir içinde ne yasak

```
neverallow xrom_isolated_payload self:capability {
    sys_module sys_rawio sys_admin sys_boot sys_time sys_ptrace
    net_admin net_raw dac_override dac_read_search };
neverallow xrom_isolated_payload self:capability2 { mac_admin mac_override syslog };
```
Çekirdek modülü yükleyebilen, fiziksel belleğe dokunabilen, mount yapabilen veya
saati kurabilen bir payload izole değildir: guest çekirdeğinin dünya görüşünü
yeniden kurabilir ve boot'ta ölçülen her şey anlamını yitirir.

```
neverallow xrom_isolated_payload { domain -microdroid_manager -crash_dump
                                   -microdroid_payload }:process
           { ptrace signal sigkill sigstop };
```
Payload, VM içindeki başka hiçbir şeyi inceleyemez veya ona karışamaz.
`crash_dump` tombstone toplayabilsin diye istisna.

```
neverallow xrom_isolated_payload self:packet_socket *;
neverallow xrom_isolated_payload self:rawip_socket *;
neverallow xrom_isolated_payload block_device:blk_file *;
```
Payload host'a yalnızca `microdroid_manager`'ın verdiği vsock üzerinden ulaşır.
Ham blok cihazı erişimi özellikle önemli: `instance.img` ve şifreli depolama
imajı manager tarafından mount ediliyor; bunları ham açabilen bir payload
guest'in kendi bütünlük kontrollerini atlayabilir.

```
neverallow xrom_isolated_payload microdroid_manager:file { read write open };
neverallow xrom_isolated_payload microdroid_manager:dir { read open add_name remove_name };
```
pvmfw'ın türettiği malzeme hiçbir payload tarafından okunamaz. Per-VM sırrı VM
kimliğinin kökü; okuyabilen bir payload, VM'i hem host'a hem uzak attestasyona
karşı taklit edebilirdi.

Ağ `neverallow`'u (`tcp_socket`, `udp_socket`) **bilerek yok**: AVF'nin
`RELEASE_AVF_ENABLE_NETWORK` bayrağı açıkken AOSP `microdroid_payload`'a soket
izinleri verebiliyor ve bir `neverallow` ile çelişen bir `allow` build hatasıdır.
Bunun yerine ağ kısıtı **kodda** uygulanıyor: `MicrodroidVmBuilder`
`customConfig`'i `nullopt` bırakıyor, yani `networkSupported` hiç istenmiyor.

Benzer şekilde AOSP'nin `microdroid_payload`'a zaten verdiği yetenekler
(`kmsg_device`, `devpts`, `microdroid_manager:vsock_socket`) için neverallow
yazılmadı — aynı nedenden.
