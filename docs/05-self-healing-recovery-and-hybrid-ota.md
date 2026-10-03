# 05 — Kendi Kendini Onaran Kurtarma ve Hibrit OTA

Bu belge X-ROM'un üçüncü oturumunu anlatır: tehdit algılandığında cihazın ne yaptığı,
güncelleme yolunun nasıl karar verdiği ve bir açılışın sağlamlığının nasıl doğrulandığı.

Önceki belgeler: [01 — AVF/pKVM temeli](01-avf-pkvm-foundation.md),
[02 — SELinux ve izinler](02-selinux-and-permissions.md),
[03 — native servis ve entegrasyon](03-native-service-and-integration.md),
[04 — vsock veri düzlemi ve payload imzalama](04-vsock-data-plane-and-payload-signing.md).

> **Bu belgeyi okurken dikkat edilmesi gereken şey:** §F'de listelenen 15 tasarım
> düzeltmesi, gelen gereksinimin olduğu gibi uygulanmadığı yerleri anlatır. Hiçbiri
> tercih meselesi değil; her biri ya build'i kıran, ya bir güvenlik özelliğini
> çalışmıyormuş gibi gösteren, ya da sessizce daha zayıf bir davranışa yol açan bir
> sorunun çözümüdür. §G'de ise **çözülmemiş** bir risk duruyor ve orada çözülmemiş
> olarak kalacak.

---

## İçindekiler

- [A. Mimari ve katman ayrımı](#a-mimari-ve-katman-ayrımı)
- [B. Karantina: algılamadan reboot'a kadar olan sıra](#b-karantina-algılamadan-reboota-kadar-olan-sıra)
- [C. `xrom_vault` ve hibrit OTA](#c-xrom_vault-ve-hibrit-ota)
- [D. Post-boot integrity ve boot-loop guard](#d-post-boot-integrity-ve-boot-loop-guard)
- [E. Testler ve enjekte edilen regresyonlar](#e-testler-ve-enjekte-edilen-regresyonlar)
- [F. Tasarım düzeltmeleri (15 madde)](#f-tasarım-düzeltmeleri)
- [G. Bilinen sınırlar ve açık riskler](#g-bilinen-sınırlar-ve-açık-riskler)

---

## A. Mimari ve katman ayrımı

Sistem iki katmana ayrıldı ve bu ayrım kozmetik değil.

**Karar katmanı** — `common/recovery/` ve `common/ota/`. Saf C++17, hiçbir Android
header'ı yok, saat yok, binder yok, dosya I/O yok, global yok. Her karar bir struct'ın
saf fonksiyonu.

**Yürütme katmanı** — `services/recovery/xrom_sentineld/`,
`services/ota/xrom_ota_installer/`, `bootable/xrom_recovery_gate/`. Bunlar `/misc`'e
yazar, netd ile konuşur, blok cihazı açar, reboot ister.

Ayrımın sebebi şu: bu kodun işi **bir kez**, bir olay sırasında, **zaten bozulmuş bir
cihazda** doğru çalışmak. İnciden sonra etkileşimli olarak hata ayıklanamaz. Yani her
dalın — özellikle sadece olay anında çalışanların — build makinesinde
çalıştırılabilmesi gerekiyor. Karar katmanının saf olmasının tek sebebi bu.

| Bileşen | Yol | Ne yapar |
|---|---|---|
| `BcbMessage` | `common/recovery/` | `bootloader_message` yerleşimi, misc bölge haritası, **append** semantikli render |
| `RecoveryDecision` | `common/recovery/` | Hibrit karar motoru (11 sinyal, 4 aşama) + IPv4/CIDR ayrıştırıcı |
| `QuarantinePlan` | `common/recovery/` | Algılama ile reboot arasındaki **sıra** |
| `VaultMetadata` | `common/recovery/` | Vault kaydı + post-boot karşılaştırma |
| `BootAttemptPolicy` | `common/recovery/` | İki sayaçlı boot-loop guard |
| `OtaManifest` | `common/ota/` | `update.json`: doğrulama + imzalanan baytların serileştirmesi |
| `OtaVerifier` | `common/ota/` | Aşamalı kabul sırası + çift imza AND'i |
| `xrom_sentineld` | `services/recovery/` | Binder servisi ve karantina yürütücüsü |
| `xrom_ota_installer` | `services/ota/` | Vault'a yazan **tek** domain; ağı yok |
| `xrom_recovery_gate` | `bootable/` | Recovery image içinde çalışan karar verici |

`libxrom_recovery_core` hem `host_supported` hem `recovery_available`. İkincisi önemli:
recovery gate bu kütüphaneyi **recovery image içinden** linkler, yani aynı karar kodu
hem koşan sistemde hem recovery'de aynı baytlardır. Bu sayede `previewRecoveryDecision()`
sağlıklı bir cihazda verdiği cevabın, bir olay sırasında gerçekten verilecek cevap
olduğunu iddia edebilir.

---

## B. Karantina: algılamadan reboot'a kadar olan sıra

### B.1 Sıra bir tercih değil

`BuildPlan()` bir severity ve bir policy'den sabit, sıralı bir adım listesi üretir.
Sıranın neden bu olduğu:

```
lock-folder  →  stash-evidence-in-pvm  →  cut-network  →  [notify-user]
             →  record-boot-attempt  →  arm-recovery-boot  →  reboot
```

- **Kilitleme önce**, çünkü izlenen dizin değişmeyi bırakmadan taşınacak kanıtın
  güvenilir olduğu söylenemez.
- **Kanıt taşıma, ağ kesmeden önce**, çünkü ağın kesilmesi *görünür bir sinyal*.
  Kesintiyi önceden gören düşmanca bir süreç, taşınmamış kanıtı yok etmek için bir
  pencereye sahip olur.
- **Ağ kesme, BCB arm edilmeden önce**, çünkü "karar verildi" ile "cihaz gitti"
  arasındaki aralık, aksi halde uzaktan komutların hâlâ ulaştığı bir aralıktır.
- **BCB arm etme sondan bir önce**, çünkü dönüşü olmayan nokta orası. O andan sonra
  kalan adımların hepsi atlanması güvenli olanlar olmalı.

### B.2 Her adımın bir başarısızlık davranışı var

| Adım | `OnFailure` | Neden |
|---|---|---|
| `kLockFolder` | `kContinue` | Kilitlenemeyen bir dizin yanıtı yanlış yapmaz, eksik yapar |
| `kStashEvidenceInPvm` | `kEscalate` | **Kendi kanıtını koruyamayan bir karantina onu yok eder** |
| `kCutNetwork` | `kContinue` | Ağ kesme derinlemesine savunma; netd cevap vermedi diye karantinadan vazgeçmek kesin bir gerileme olurdu |
| `kNotifyUser` | `kContinue` | Diyaloğu hiç görmeyen kullanıcı yine de doğru güvenlik yanıtını almalı |
| `kArmRecoveryBoot` | `kAbortWithoutReboot` | Yarım yazılmış bir misc, bootloader'a yorumlayamayacağı bir komut bırakabilir; **açılamayan bir cihaz kendini karantinaya da alamaz** |
| `kReboot` | `kContinue` | Son adım |

### B.3 BCB: append, replace değil

`/misc`'in ilk 2048 baytı `bootloader_message`. Alanları:

| Alan | Ofset | Boyut |
|---|---|---|
| `command` | 0 | 32 |
| `status` | 32 | 32 (Froyo'dan beri kullanılmıyor) |
| `recovery` | 64 | **768** |
| `stage` | 832 | 32 |
| `reserved` | 864 | 1184 |

`recovery` alanı **paylaşılan bir kanal**: `uncrypt`, `RecoverySystem`, `update_engine`
ve A/B slot mantığı hepsi oraya komut kuyruğa alır. Bekleyen bir komut anlamlıdır.

Bu yüzden `Render()`:

1. Mevcut seçenekleri **korur**, sıralarını bozmaz;
2. Yeni seçenekleri yalnızca yoksa ekler;
3. `--xrom-reason=` varsa eskisini değiştirir (iki tane olması alanı belirsiz yapar);
4. 768 bayta sığmayan birleşik alanı **reddeder, asla kırpmaz** — kırpılmış bir seçenek
   *başka bir seçenektir*;
5. `changed` raporlar; değişmemiş bir BCB **yeniden yazılmaz**.

Sonuncusu iki sebepten önemli: flash'ın sonlu bir silme bütçesi var ve bazı
denetleyicilerde misc'e yarım kalan bir yazma geri döndürülemez.

Yazma `libbootloader_message` üzerinden yapılır, ham blok yazmasıyla değil (§F, #1).

### B.4 misc bölge haritası — ve neden oraya sayaç koymuyoruz

```
0       – 2 KiB    BCB (bootloader_message)
2 KiB   – 16 KiB   vendor bootloader alanı
16 KiB  – 32 KiB   wipe_package (uncrypt / recovery)
32 KiB  – 64 KiB   SYSTEM_SPACE (AOSP feature'ları, örn. misc_virtual_ab_message)
```

32 KiB'den sonrası bootloader, recovery ve uncrypt'in **aralarında anlaştığı ve
yapılandırılamayan** ofsetlerle paylaşılır. Oraya park edilen bir X-ROM sayacı, aynı
bölgeyi kullanan bir sonraki platform güncellemesiyle çakışmayı bekleyen bir mayındır
(§F, #4).

### B.5 İptal penceresi

30 saniyelik, kullanıcı tarafından iptal edilebilir bir pencere var — ama **CRITICAL
severity'de varsayılan olarak yok** (§F, #7).

Gerekçe açık: UI, şüphe altındaki sistemin bir parçası. "Tehdit algılandı, iptal etmek
için dokunun" diyen bir diyalog, cihazı ele geçiren şeye verilmiş bir kontrol
yüzeyidir. CRITICAL tam olarak o bileşene en az güvenilmesi gereken seviyedir.

İptal iki koşulu birden gerektirir:

1. Sentinel'ın diyalogla birlikte verdiği **tek kullanımlık token** — diyaloğu hiç
   görmemiş bir system-uid bileşenin onu kapatamaması için;
2. **Keyguard-authenticated kullanıcı** onayı — ekranda diyalog çizebilen herhangi bir
   sürecin bir güvenlik yanıtını durduramaması için.

İkisi birlikte gerekli: sadece uid kontrolü herhangi bir sistem bileşeninin herhangi bir
karantinayı iptal etmesine izin verirdi; sadece token ise log'u okuyan UI-dışı bir
sürecin kullanıcıymış gibi yapmasına.

---

## C. `xrom_vault` ve hibrit OTA

### C.1 İki partition, bir tane değil

```
/dev/block/by-name/xrom_vault        image   — yalnızca xrom_ota_installer yazar
/dev/block/by-name/xrom_vault_meta   64 KiB  — VaultRecord; sentinel yazar
```

Kayıt, image partition'ının içinde **yaşayamaz**. Sentinel'ın kendi boot-loop sayacını
artırması gerekiyor; SELinux blok cihazlarını etiketler ve **ofsetleri ayırt edemez**.
Tek cihaz paylaşmak, write-monopoly neverallow'unun sentinel'ı istisna olarak
saymasını gerektirirdi — ve o zaman gereksinimin istediği özellik ortadan kalkardı.
64 KiB, ikisinden de ucuz (§F, #5).

`xrom_vault` **super'ın dışında**, sabit bir partition. Süper'in içinde olmak, yedeği
*yalnızca yedeği olduğu şeyin içinde* tutmak demek; super yeniden yazıldığında yedek de
gider.

### C.2 `VaultRecord`

384 bayt, packed, `static_assert`'li. Alanlar: magic (`XROMVLT`), `record_version`,
`state`, `vault_hashtree_root[32]`, `system_hashtree_root[32]`, `package_sha256[32]`,
`package_bytes`, `security_version`, `build_fingerprint[96]`, `written_unix`,
`integrity_failures`, `reserved[155]`.

İki ayrıntı:

- **Boş kayıt sıfır değil.** Silinmiş bir flash `0xFF` okur, kasten sıfırlanmış biri
  `0x00`. Üçüncü bir desen (`reserved` alanında `0xA5`) "X-ROM tarafından
  başlatıldı"yı ikisinden de ayırt edilebilir yapar.
- **`state` beş değerli**: `kEmpty`, `kWritten`, `kVerified`, `kMismatch`,
  `kRolledBack`. `kWritten` asla `kVerified` gibi davranmaz: baytların yazıldığını ama
  geri okunup karşılaştırılmadığını söyleyen bir kayıt, iddiası kontrol edilmemiş bir
  kayıttır.

### C.3 Aşamalı OTA kabulü

Hiçbir pahalı veya geri döndürülemez şey, ucuz ve belirleyici her şey geçmeden olmaz:

| # | Aşama | Ne kontrol edilir |
|---|---|---|
| 1 | `manifest-signature` | **Her iki** ayrı imza, manifest'in tek bir alanı veri olarak okunmadan önce |
| 2 | `manifest-format` | Ayrıştırmanın imzalanan baytlara **sadık** olması (yeniden serileştir ve karşılaştır) + format + hedef parmak izi |
| 3 | `anti-rollback` | `security_version` — **pinlenmiş anchor'lardan**, manifest'in kendi iddiasından değil |
| 4 | `validity-window` | Saat yoksa **reddet**; recovery'deki cihaz tam da saatin yanlış olduğu durumda |
| 5 | `size-ceiling` | Beyan edilen boyut tavana karşı — **tek bir bayt çekilmeden önce** |
| 6 | `fetch` | Gelen uzunluk beyana karşı |
| 7 | `package-digest` | Gelen SHA-256 beyana karşı |
| 8 | `install` | — |
| 9 | `hashtree-root` | **Yazılan** image'ın kökü, manifest'in söz verdiği köke karşı |

Aşama 2'deki sadakat kontrolü, bir JSON katmanının kendiyle çelişmesini yakalayan tek
şey: tekrarlanan anahtarlar, yanlış genişliğe ayrıştırılan bir sayı, sessizce düşen bir
alan. İmza ham baytları kapsar, yani üzerinde hareket edilen yapının o baytlara karşılık
gelmesi gerekir. **Hiçbir imza bunu yakalayamaz**, o yüzden kontrol var.

Aşama 9 ise doğrulanmış, eksiksiz inmiş, temiz kurulmuş ve **yine de imzalanan image'ı
üretmemiş** bir paketi yakalar.

### C.4 Çift imza: AND'in neyi savunduğu

`require_dual = true` ve `require_distinct_keys = true`.

İki algoritmanın **aynı `key_id`** altında olması — iki imza değil, bir anahtarın iki kez
sayılmasıdır. `require_distinct_keys` bunu yakalar; spec'te yoktu ve gerekli.

Bir nüans testle sabitlendi: `require_dual = false` yapıldığında RSA sinyalleri **hiç
danışılmıyor** (tabloya eklenmiyor). Yani imzalanmış ama *başarısız olmuş* bir RSA imzası
bile şüphe üretmiyor. Bu sessiz bir zayıflama ve bir knob'u çevirip build'i geçirmek
için değil (§F, #8).

### C.5 Installer'ın ağı yok

`xrom_ota_installer` sepolicy'de **her socket class'ından** men edilmiş. Recovery image
indirir, installer yazar. Bu ayrım sayesinde writer'ı ele geçirmek, saldırgana bir
teslimat kanalı **vermez**. OTA yolunda iki executable olmasının sebebi bu.

---

## D. Post-boot integrity ve boot-loop guard

### D.1 Ne karşılaştırılıyor — ve neden `/system`'in tam SHA-256'sı değil

Gereksinim "her boot'ta iki partition'ın SHA-256'sını al" diyordu. `/system` birkaç GB;
her boot'ta tamamını okumak, uygulama başlatmak üzere olan bir cihazda saniyelerce flash
I/O demek. Ve **zaten yapılmış bir işi tekrarlıyor**: `/system` AVB hashtree ile
korunuyor (bootloader kernel başlamadan doğruladı) ve dm-verity her bloğu okunduğu anda
yeniden kontrol ediyor.

Bu yüzden birincil karşılaştırma **AVB hashtree root digest'leri** — 32'şer bayt, zaten
hesaplanmış, zaten authenticate edilmiş. Tam içerik digest'i kaldırılmadı:
`IntegrityDepth::kDeep` olarak opt-in duruyor ve kullanım yeri boot'u gate'lemek değil,
ucuz karşılaştırmanın **zaten bulduğu** bir uyuşmazlığı açıklamak (§F, #9).

### D.2 İki canlı digest gerekli — kayıt tek başına yetmez

İlk taslağın imzası `CompareHashtreeRoots(live_system, record)` idi ve **yanlıştı**.
Kayıt install anındaki digest'leri sakladığı için *bir şeyin* değiştiğini kanıtlayabilir
ama *hangi partition'ın* değiştiğini söyleyemez. Çareler birbirinin tersi:

| Durum | Çare |
|---|---|
| slot değişti, vault sağlam | vault'tan **geri yükle** |
| vault değişti, slot sağlam | vault'u **yeniden yaz** — sakın geri yükleme |
| ikisi de değişti | bilinen iyi yerel kopya yok → kurtarma dışarıdan gelmeli |

Yanlış tarafı söyleyen bir log, operatöre sağlam bir system image'ı bilinmeyen bir vault
ile değiştirtir. İmza `CompareImages(live_system, live_vault, record, depth)` (§F, #11).

Ayrıca: kayıttaki iki root install anında **eşit olmak zorunda** (tek image iki
partition'a yazılıyor). Eşit değillerse vault yanlış yazılmış demektir ve bu,
karşılaştırmalardan **önce** yakalanır. Aksi halde hata "vault değişti" diye raporlanır
ve operatörü kurcalama aramaya yönlendirir.

### D.3 Üç değerli verdict

`kMatch` / `kMismatch` / **`kInconclusive`**. Üçüncüsü en önemlisi: "kontrol edemedim"
ile "kontrol ettim ve farklılar"ın çaresi farklı. Okunamayan bir vault'u mismatch'e
katmak, sahadaki ilk birkaç bozuk kayıt yüzünden herkesi gerçek alarmı yok saymaya
alıştırır.

Aynı sebeple **boş vault bir mismatch değil**: hiç OTA kurulmamış bir cihazda fallback
yoktur; bunu kurcalama diye raporlamak her yeni cihazın ilk boot'ta alarm vermesi demek.

### D.4 İki sayaç, iki başarısızlık sınıfı

| Sayaç | Sahibi | Ne sayar | Nerede |
|---|---|---|---|
| `tries_remaining` | bootloader | userspace'e **ulaşmayan** boot | misc @2048 — X-ROM **sadece okur** |
| `integrity_failures` | sentinel | ulaşıp integrity'de **çakılan** boot | `VaultRecord` |

`tries_remaining` mükemmel boot olup userspace'e ulaşan, post-boot karşılaştırmada
başarısız olan ve aynı duruma reboot eden bir cihazı **yapısal olarak göremez**:
bootloader'ın gözünde o boot'ların hepsi başarılı. Sayaç kıpırdamaz ve cihaz sonsuza
dek döner (§F, #4).

`tries_remaining_floor` varsayılan **1, sıfır değil**. Sıfırda bootloader zaten vazgeçmiş
ve slot değiştirmeye başlamış oluyor; sıfırı beklemek, X-ROM'un ölmekte olan bir slot
hakkında hiç söz hakkı olmaması demek — ki vault'un işe yarayacağı tek pencere orası.

Bu invariant bir **testle** sabitlendi, yorumla değil:

```cpp
EXPECT_FALSE(xrom::recovery::XromMayWritePlatformBootCounter());   // daima false
```

Fonksiyon olmasının sebebi bu: bir sonraki değişikliğin yüzleşmek zorunda kalacağı bir
assertion, okumayabileceği bir yorumdan daha dayanıklı.

### D.5 Hangi çare

Recovery **birinci**, slot değişimi **ikinci** tercih — çünkü recovery vault'tan
hiçbir şeyi atmadan geri yükleyebilir, slot değişimi ise mevcut image'ı terk eder ve
iki slotu birlikte güncellenmiş bir cihazda eşit derecede bozuk birine inebilir.

Bootloader'ın recovery denemeleri tükendiyse (`recovery_tries_remaining == 0`) recovery
arm edilmez: bootloader'ın dinlemeyeceği bir recovery, gelmeyen bir recovery'den
kötüdür — cihaz aynı durumda geri gelir ve başarısızlık artık görünmez olmuştur. O zaman
slot değişimine geçilir. **İkisi de yoksa** `kNone` döner ama sebebiyle: her iki çarenin
de değerlendirilip reddedildiğini gizlemek, operatörün bilmesi gereken tek şeyi gizlemek.

---

## E. Testler ve enjekte edilen regresyonlar

### E.1 Sayılar

| Suite | Test | Kontrol | Hata |
|---|---|---|---|
| `xrom_avf_core_test` | 50 | 182 | 0 |
| `xrom_shared_core_test` | 49 | 274 | 0 |
| **`xrom_recovery_core_test`** | **122** | **457** | **0** |
| **`xrom_ota_core_test`** | **83** | **245** | **0** |
| **Toplam** | **304** | **1158** | **0** |

Bu oturumda eklenen: **205 test**. Önceki 99 test değişmeden geçiyor.

Ayrıca: `payload_signing_roundtrip.sh` **34/34**, `ota_signing_roundtrip.sh` **37/37**,
`xrom_preflight.py` **29 grup / 0 hata / 2 beklenen uyarı**.

### E.2 İki implementasyonun birbirine karşı test edilmesi

`ota_signing_roundtrip.sh` adım 4, bu projedeki en değerli tek test:

Python aracı `update.json`'ı üretir, C++ tarafı onu ayrıştırıp `Serialize()` ile yeniden
üretir ve imzalanan baytlarla karşılaştırır. Test, Python'un yazdığı dosyadan **aynı alan
değerlerini** okuyup onlarla bir C++ programı derler ve `OtaManifest::Serialize()`
çıktısını dosyanın baytlarıyla karşılaştırır. Şu an iki tarafta da 611 bayt, birebir aynı.

Bu test olmadan ikisi sessizce ayrışabilir ve sonuç **doğru ama yanıltıcı bir ret** olur:
cihaz, hiç yeniden üretemeyeceği baytlar üzerinde geçerli bir imza görür ve reddeder.
Bu bir bozuk anahtar gibi görünür ve bozuk anahtar olarak teşhis edilir.

### E.3 Enjekte edilen 7 regresyon — 7'si de yakalandı

| # | Regresyon | Yakalayan |
|---|---|---|
| R1 | BCB merge → memset-and-write (kuyruktaki uncrypt/OTA komutları sessizce silinir) | host testleri: `RenderPreservesOptionsAlreadyQueuedInMisc`, `RenderReplacesAnOlderXromReason` |
| R2 | Bir recovery sinyali `kUnknown` yerine `kClean`'e default olur (**fail-open**) | host testleri **+** preflight `[recovery fail-secure defaults]` |
| R3 | Sentinel'a vault image write verilir (monopoly kırılır) | preflight `[vault write monopoly]` |
| R4 | OTA installer'a TCP socket verilir (writer'a teslimat kanalı) | preflight `[vault write monopoly]` |
| R5 | `Serialize()` alan sırası kayar (her imza ölür) | roundtrip adım 4 **+** verifier sadakat testi |
| R6 | misc neverallow spec'in istediği tek-istisna biçimine geri alınır (**build break**) | preflight `[misc neverallow]` |
| R7 | CRITICAL'de iptal penceresi açılır | preflight `[recovery fail-secure defaults]` |

### E.4 Regresyon harness'ının bulduğu test hatası

R1 ilk çalıştırmada **kaçırıldı** — ama regresyon yakalanmadığı için değil. Test ikilisi
**segfault** ile çöktü: `ParseRecoveryOptions(...)[2]` sınır dışı okuma yapıyordu.

Bu önemli bir ders ve buraya yazılması gerekiyor: **sınır kontrolsüz bir indeks, bir
testte "regresyon tespit edildi"yi "test altyapısı çöktü"ye çevirir.** Çökme hiçbir özet
satırı üretmez; runner bunu bir tespit olarak değil, bir altyapı arızası olarak okur.

Düzeltme: testlerde sınırsız indeks kalmadı (`OptionAt`, `StepAt`). `QuarantinePlan_test`
için bir de ek sebep çıktı — çok satırlı `#define`'ın devam satırları `#` ile
başlamadığı için preflight'ın denge kontrolü onları tutuyor ve dosyayı dengesiz
bildiriyordu. Makro inline fonksiyona çevrildi.

---

## F. Tasarım düzeltmeleri

Gelen gereksinimde 15 yerde değişiklik yapıldı. Hiçbiri üslup tercihi değil.

### #1 — BCB ham blok yazmasıyla değil, `libbootloader_message` ile yazılır ✅

**Gereksinim:** `blk_file write` ile `/misc`'e `boot-recovery` yaz.

**Sorun:** Ham bir yazma, `recovery` alanını **siler**. O alan paylaşılan bir kanal;
`uncrypt`, `RecoverySystem`, `update_engine` ve A/B slot mantığı oraya komut kuyruğa
alır. Kuyruktaki bir wipe veya yarım kalmış bir OTA **sessizce** kaybolur ve cihaz bir
sonraki reboot'ta yanlış şeyi yapar — neyin kaybolduğuna dair hiçbir kayıt olmadan.

**Çözüm:** Oku–birleştir–yaz. Birleştirme saf çekirdekte (`Render`), çünkü
`libbootloader_message` misc partition'ı olmadan unit test edilemez ve birleştirme tam
olarak test edilmesi gereken kısım.

### #2 — Spec'in misc `neverallow`'ı AOSP build'ini kırar ✅

**Gereksinim:** `neverallow { domain -xrom_avfd } misc_block_device:blk_file write;`

**Sorun:** `neverallow` bir öneri değil; policy derlenirken **tüm** allow kurallarına
karşı kontrol edilir — AOSP'ninkiler de dahil. AOSP misc write'ı meşru olarak veriyor:

| Domain | Neden |
|---|---|
| `recovery` | BCB'yi okur/temizler; `fastbootd` ve `misc_writer` bu domain'de |
| `uncrypt` | `/data`'daki paketi `/cache` bloklarına haritalar, `wipe_package` yazar |
| `update_engine` | A/B slot metadata'sını günceller |
| `hal_boot_default` | Boot control HAL — `tries_remaining`'i **o** düşürür |
| `init` | Erken boot misc işlemleri |

Kural girerse `sepolicy` build'i beş domain için neverallow ihlali verir ve `m`
başarısız olur. **Kural hiçbir şeyi sertleştirmez, sadece derlemeyi durdurur.**

**Çözüm:** Açık allowlist:

```
neverallow { domain -xrom_sentineld -recovery -uncrypt -update_engine
             -hal_boot_default -init } misc_block_device:blk_file write;
```

Bu gerçek bir kısıt (listede olmayan her domain reddedilir) ve policy'nin
sağlayabileceği bir kısıt. Preflight'ta bir grup bunu kilitliyor (R6 ile doğrulandı).

### #3 — `xrom_avfd`'ye blok cihazı write verilmez ✅

**Gereksinim:** `allow xrom_avfd misc_block_device:blk_file { write open };`

**Sorun:** İki sebeple.

Birincisi kendi kısıtınla çelişiyor: `IXIsolationService` ve vsock düzlemi donmuş.
`xrom_avfd` şu an `/dev/kvm`'i bile açamıyor — bu bilinçli bir neverallow:

```
neverallow xrom_avfd kvm_device:chr_file *;
# daemon açabiliyorsa, daemon'daki bir bug bir hypervisor-escape primitive'tir
```

Bu domain'e misc'e ham blok yazma vermek, projenin en sıkı korunan yetki sınırını
genişletmek.

İkincisi **yetki alanı ayrımı**: BCB yazmak + ağı kesmek + reboot etmek, "şu payload'la
bir VM başlat"tan çok daha büyük bir yetki. Aynı domain'e koymak, payload doğrulama
yolundaki bir bug'ı **telefonu reboot edebilen** bir bug'a çevirir.

**Çözüm:** Ayrı domain (`xrom_sentineld`), ayrı binder arayüzü (`IXRecoveryService`,
yeni `xrom_recovery` aidl_interface). `IXIsolationService`'e **tek bir method
eklenmedi**. İki arayüz arasındaki tek etkileşim: sentinel kanıtı pVM'e taşımak için VM
istediğinde, diğer her client'ın kullandığı aynı arayüzü kullanır ve aynı
`IsolationPolicy`'ye tabidir — ayrıcalıklı yol yok.

### #4 — Boot counter zaten var; yeniden icat etmek misc'te çakışır ✅

§D.4'te anlatıldı. Özet: `tries_remaining` **okunur, asla yazılmaz**; X-ROM kendi
sayacını vault kaydında tutar. `XromMayWritePlatformBootCounter()` daima `false` ve bu
bir testle sabit.

### #5 — "SELinux süreç çıkınca vault'u otomatik read-only yapar" diye bir şey yok ✅

**Gereksinim:** "`xrom_ota_installer` vault'a yalnızca OTA sırasında yazabilir; **o süreç
çıkınca vault read-only olur**."

**Sorun:** SELinux'ta böyle bir mekanizma yok. Policy **statik**: bir domain bir
permission'a ya sahiptir ya değildir; süreç yaşam döngüsüne, zamana veya "OTA sırasında"
gibi bir moda bağlı değişmez. Koşullu izin yok. `neverallow` da bir çalışma zamanı
mekanizması değil, derleme zamanı kısıtı.

Yani cümlenin ikinci yarısı, birincisinin zaten sağladığı şeyi sağlıyormuş gibi görünüp
hiçbir şey yapmıyor.

**Çözüm — üç katman, hiçbiri "otomatik" değil:**

1. **Vault asla `rw` mount edilmez.** `recovery.fstab`'da `ro` + `recoveryonly`. Blok
   cihaza doğrudan yazılır — `update_engine`'in inactive slot'a yazarken kullandığı
   model. "Süreç çıkınca read-only olur" değil, **her zaman read-only**.
2. **İzin tek domain'de**, neverallow ile uygulanıyor (R3/R4 ile doğrulandı).
3. **Vault AVB hashtree kapsamına alındı** (`BOARD_AVB_XROM_VAULT_*`, rollback index
   location 4). Bu benim ek önerimdi ve spec'te yoktu: imzalı bir vbmeta ile eşleşmeyen
   her yazma boot'ta tespit edilir. Post-boot karşılaştırmanın elinde saklanmış bir
   digest'ten fazlası — **kriptografik bir çapa** olur.

Sonuç gereksinimden **daha güçlü**: vault süreç çıktıktan sonra değil, *her zaman*
read-only ve yazılabilir olmanın tek yolu denetlenebilir bir yol.

Bu düzeltmenin bir yan ürünü daha var: **iki partition** (§C.1). Kayıt image
partition'ında yaşayamaz, çünkü SELinux ofsetleri ayırt edemez.

### #6 — Pinlenmiş `140.82.112.0/20` DNS kontrolü zayıf ve kırılgan ✅

**Gereksinim:** "DNS cevabı `github.com → 140.82.112.0/20` aralığında mı? → temizse devam."

**Sorun — üç ayrı:**

1. **Bir güven sinyali değil.** CIDR, DNS cevabının *şeklini* kontrol eder, *kimliğini*
   değil. Kendi resolver'ını kontrol eden saldırgan istediği adresi o aralıktan döndürür
   — aralık kontrolü tam olarak onu kandırması en kolay olan kontrol.
2. **Kırılgan.** `140.82.112.0/20` GitHub'ın *bugün* yayınladığı aralık. Değişir, CDN'e
   geçer, ya da senin update host'un zaten GitHub olmaz — ve recovery, ağ tamamen
   sağlıklıyken vault'a düşmeye başlar. **Sessizce**: kimse nedenini anlamaz, çünkü
   "güvenlik özelliği çalışıyor" gibi görünür.
3. **Yanlış yerde yük taşıyor.** Spec'in karar ağacında bu kontrol TLS pin'inden *önce*
   ve onu geçmek bir sonraki adıma ilerletiyor: en zayıf kontrol, en güçlüsünün ön koşulu.

**Çözüm — kaldırılmadı, rolü değiştirildi:**

- `kSuspicious` → şüphe → vault. **İşe yarıyor.**
- `kClean` → remote'u **yetkilendirmez**. Yetki için diğer 10 sinyalin de temiz olması
  gerek; temiz bir DNS cevabı hiçbir şey eklemiyor.
- `pinned_cidrs` boş ve kontrol açıksa → **şüphe**, geçiş değil. Pin'leri doldurmayı
  unutan bir build ağa değil vault'a düşer.
- Yükü taşıyan kontrol `tls_pin_matched` — recovery image'ına derlenmiş public-key
  SHA-256 pin'i.

Ek olarak **IP-literal URL'ler reddediliyor**: pinlenmiş bir sertifikanın eşleşeceği bir
subject name'i vardır, bir adresin yoktur. IP'ye giden URL, TLS pin'inin tamamını atlar.

### #7 — CRITICAL'de iptal penceresi varsayılan olarak kapalı ✅

§B.5'te anlatıldı. `allow_cancel_at_critical = false`, iptal token + keyguard onayı
gerektirir, ve her girişim — başarılı olanlar dahil — loglanır.

### #8 — Çift imza bir AND; neyi savunduğunu doğru söylemek gerekiyor ✅

**Gereksinim:** Ed25519 + RSA-4096, gerekçe olarak ima edilen: biri kırılırsa diğeri yedek.

AND olarak uygulanması **doğru**. Yanlış olan gerekçe. "Ed25519 kırılırsa RSA kurtarır"
bir tehdit modeli değil: eğri primitifleri çöken bir dünyada RSA, zaten kırılganlığı
kanıtlanmış bir doğrulama yolunu koruyor olur ve o yetenekteki bir saldırganın OTA
sahteciliğinden daha iyi seçenekleri vardır.

Çift imzanın gerçekten kapattığı iki şey var ve ikisi de **sık** oluyor:

1. **Tek doğrulama yolundaki bug** — iki farklı implementasyonun aynı hatayı yapması gerekir.
2. **Tek imza anahtarının ele geçirilmesi** — iki ayrı key ceremony gerekir.

Bedeli gerçek ve gömülmek yerine söylenmeli: **iki anahtar, iki ceremony, iki rotation
takvimi** ve ikisinden biri eksikse başarısız olan bir imzalama aracı.

Ek: `require_distinct_keys` (§C.4) ve `require_dual = false`'un RSA sinyallerini
tamamen devre dışı bırakması — ikisi de spec'te yoktu, ikisi de testle sabitlendi.

### #9 — `/system`'in tam SHA-256'sı dm-verity'nin tekrarından ibaret ✅

§D.1'de anlatıldı. Birincil karşılaştırma AVB hashtree root'ları; tam digest
`kDeep` olarak opt-in. Rapor hangi derinliğin koştuğunu **söylüyor**, çünkü "image'lar
eşleşti" kaydı ucuz bir kontrol ile tam bir kontrol arasında ayrım yapmıyorsa yanıltıcı.

### #10 — "Ağı kernel seviyesinde kes" — ama `CONFIG_BPF_SYSCALL` kapalı ⚠️ **AÇIK RİSK**

**Gereksinim:** "ağı kernel seviyesinde kes."

**İki sorun:**

1. Kernel'e yama yazmıyoruz ve `CONFIG_BPF_SYSCALL` kapalı kalacak — bu senin kısıtın ve
   Session 1'den beri `device/x1/kernel/gki_xrom_pkvm.fragment` satır 93'te duruyor.
   Yani "kernel seviyesinde" ifadesi kullanılamayan bir mekanizmayı ima ediyor.
2. Dürüst tarif: **netd'nin nftables zinciri**. Filtreleme gerçekten kernel'de olur
   (nftables bir kernel alt sistemi), ama politikayı userspace'te netd kurar. "Kernel
   patch" değil, "userspace'in yapılandırdığı kernel filtreleme" — ve bu ayrım tehdit
   modeli için önemli: netd'ye yeterli yetkiyle ulaşabilen bir süreç bunu geri alabilir.

**Uygulanan tasarım — üç bağımsız katman, her biri ayrı raporluyor:**

| Katman | Mekanizma | Ne zaman çalışır |
|---|---|---|
| `netd-firewall-chain` | `INetd::firewallEnableChain` (OEM zinciri) | netd çalışıyorsa |
| `interface-down` | `SIOCSIFFLAGS` ioctl, `CAP_NET_ADMIN` | **netd olmadan da** |
| `quarantine-property` | `sys.xrom.network.quarantined=1` + init trigger | kayıt + tetikleyici |

Değerlendirme kuralı "tüm katmanlar başarılı olmalı" **değil**: katmanlar bir dizinin
adımları değil, bağımsız mekanizmalar. Hepsini istemek, netd'si bozuk bir cihazın hiç
karantina yapamaması demek. Ama "en az biri başarılı" mutlaka `degraded` bayrağıyla
birlikte geliyor, yoksa yarı bozuk bir ağ kesme log'da tam bir kesme gibi okunur.

**Boş katman listesi bir başarı değil.** Her katmanı kapatan bir konfigürasyon
`network_cut = false` üretir, çünkü hiçbir şeyin yapmadığı bir kesmeyi raporlamak tam
olarak bu fonksiyonun engellemek için var olduğu sessiz başarısızlık.

#### ⚠️ ÇÖZÜLMEMİŞ RİSK: bu kernel'de netd çalışıyor mu?

**Bilmiyorum ve burada çözülmemiş olarak duruyor.**

X-ROM `CONFIG_BPF_SYSCALL` kapalı derleniyor. Android 12+'da netd kendi işlevlerinin
bazıları için eBPF kullanıyor ve `bpfloader` bir early-init servisi. Yani netd'nin bu
kernel'de normal çalışıp çalışmadığı **kaynak ağacından belirlenemez** — cihaz gerekir.

İki olası sonuç:

- netd çalışıyorsa → yukarıdaki tasarım geçerli, `netd-firewall-chain` katmanı iş görür.
- netd çalışmıyorsa → o katman her boot'ta başarısız olur ve **`interface-down` birincil
  mekanizma haline gelir**. Ağ kesme netd'ye bağımlı olamaz.

Bu belirsizliğin tasarım üzerindeki somut etkisi şu: **katmanlar ilk başarıda durmuyor.**
Eğer dursalardı, netd'si bozuk ve ioctl katmanı çalışan bir cihaz, sağlıklı bir cihazla
**birebir aynı log'u** üretirdi ve soru asla cevaplanmazdı. Her katmanın denenmesi ve
ayrı raporlaması, gerçek bir cihazdan gelen log'un soruyu cevaplayabilmesi için.

Doğrulama yolları:

- `tools/xrom_avf_verify.sh` §13 — cihazda netd'nin kayıtlı olup olmadığını, OEM
  zincirinin kabul edilip edilmediğini ve **kesmenin gerçekten trafiği durdurup
  durdurmadığını** ölçer. Bir binder çağrısının dönmesine güvenmez.
- `NetdCompat.h` — OEM zincir id'lerinin netd sürümleri arasında donmuş bir sözleşme
  olmadığını ve hedefin `INetd.aidl`'ine karşı doğrulanması gerektiğini dosyanın
  başında söylüyor.
- `xrom_sentineld_config.json` — aynı riski konfigürasyonun yanında taşıyor.

`CONFIG_BPF_SYSCALL` **değiştirilmeyecek**. Bu senin kısıtın ve X-Defender oturumuna
kadar öyle kalıyor.

### #11 — Kayıt tek başına hangi tarafın değiştiğini söyleyemez ✅

§D.2'de anlatıldı. `CompareImages(live_system, live_vault, record, depth)`. Bu düzeltme
spec'te yoktu; implementasyon sırasında çıktı ve spec'in 4. maddesinin ("iki partition'ın
hash'ini karşılaştır") *doğru* olduğunu ama *eksik* olduğunu gösteriyor.

Aynı sırada **erişilemez bir ölü kod dalı** bulundu ve kaldırılmak yerine doğru yere
taşındı (§D.2'nin son paragrafı).

### #12 — `require_dual = false` RSA sinyallerini tamamen devre dışı bırakıyor ✅

§C.4'te anlatıldı. Spec'te yok; sessiz bir zayıflama ve testle sabitlendi.

### #13 — Boş `command` ile boş misc'e render edilen BCB hiçbir şey arm etmez ✅

`BcbRequest.command` boşsa "bootloader'ın talimatına dokunma" anlamına geliyor — meşru
bir istek. Ama misc zaten boşsa sonuç **recovery'ye boot etmeyen** bir cihaz: seçenekler
orada durur ve bootloader onlara asla bakmaz.

Bu, güvenlik tetiklemeli bir reboot için olabilecek en kötü hata modu: **her şey
çalışmış gibi görünür.** Test:

```cpp
EXPECT_FALSE(xrom::recovery::RequestsRecovery(image.message));
```

### #14 — "Log'u pVM içine taşı" ile "IXIsolationService'i değiştirme" çelişiyor ✅

**Gereksinim:** şifreli log'u pVM içinde sakla. **Kısıt:** isolation AIDL'i donmuş.

Kanıtı bir pVM'e taşımak, `IXIsolationService::submitTask` üzerinden bir task göndermek
demek; task göndermek bir `TaskClass` isimlendirmek demek. **Kanıt saklama için bir
TaskClass yok** ve `TaskClass` donmuş arayüzün bir parçası.

Payload'ın zaten hizmet verdiği sınıflardan birini yeniden kullanmak, kanıt log'unun
**bambaşka bir şey bekleyen** kod tarafından işlenmesi demek — göndermemekten kötü.

**Uygulanan:** kanıt `staging_log_path`'e mod `0600` ile yazılır ve SHA-256'sı
kaydedilir — bu gerçek, ve reboot'u atlatır. pVM handoff'u `stash_evidence_in_pvm = false`
ile kapalı ve adım detayında **sebebiyle** raporlanıyor. Isolation AIDL'i bir sonraki
açıldığında sınıfı eklemek bu bayrağı açar, başka hiçbir şey değişmez.

Bu bir hata değil, **gereksinimlerde bir çelişki** ve öyle kaydedildi.

### #15 — "OTA'yı atomik olarak hem `/system`'e hem vault'a yaz" A/B cihazda böyle çalışmaz ✅

**İki sebeple:**

1. `/system`'i `update_engine` günceller: payload'ı **inactive slot'a** uygular,
   snapshot/merge mekanizmasını yürütür ve boot control HAL ile koordine olur. Ayrı bir
   binary'den system partition'ına doğrudan yazmak üçünü de atlar ve **bootloader'ın
   metadata'sının tarif etmediği bir slot** üretir.
2. **"Atomik olarak" zaten sağlanmış** — ve bir dosya sistemi transaction'ından daha iyi
   bir şeyle: **slot switch**. Bootloader bir slot'u ancak güncelleme tamamlandıktan
   sonra bootable işaretler, yani yarım kalmış bir güncelleme *hiç geçilmeyen* bir
   slot'tur.

**Uygulanan:** installer **vault kopyasına** sahip — başka hiçbir şeyin yapmadığı kısım —
ve slot güncellemesi `update_engine`'de kalıyor. İkisine de **aynı doğrulanmış paket
baytları** veriliyor ve ikisinin sonucu da manifest'in beklediği hashtree root'a karşı
karşılaştırılıyor. Bu, "aynı imzalı paket iki yere gitti" iddiasını *varsayılan* olmaktan
çıkarıp *kontrol edilebilir* yapıyor.

---

## G. Bilinen sınırlar ve açık riskler

### G.1 Çözülmemiş: netd ve `CONFIG_BPF_SYSCALL`

§F #10'da anlatıldı. **Bu bir açık risk olarak kalıyor**, çözülmüş gibi yazılmadı.
Cihaz gerektiriyor; `xrom_avf_verify.sh` §13 ölçecek.

### G.2 Cihazda doğrulanması gerekenler

Bu sandbox'da libbinder, libbootloader_message, netd AIDL'i, BoringSSL ve Soong yok.
Dolayısıyla şunlar **derlenmedi**:

| Dosya | Neden derlenemedi |
|---|---|
| `SentinelService.cpp`, `SentinelConfig.cpp`, `PlatformActions.cpp`, `main.cpp` | libbinder, libbase, libjsoncpp, libbootloader_message, netd AIDL |
| `OtaTrust.cpp`, installer `main.cpp` | BoringSSL, libjsoncpp |
| `xrom_recovery_gate/main.cpp` | libbase, recovery ortamı |

Bu, Session 1–2'deki `IsolationService.cpp` ve `PayloadVerifier.cpp` ile aynı durum.
**Kararların tamamı** bu dosyaların dışında, saf çekirdekte ve host'ta test edildi;
derlenemeyen kısım karar vermiyor, sadece platforma dokunuyor.

Cihazda doğrulanması gereken somut şeyler:

1. `NetdCompat.h`'deki OEM zincir id'leri hedefin `INetd.aidl`'i ile uyuşuyor mu.
2. netd bu kernel'de çalışıyor mu (G.1).
3. `xrom_vault` / `xrom_vault_meta` partition'ları board'un GPT'sinde gerçekten var mı —
   `BoardConfig.mk` boyutları *istiyor*, alanı board sağlamalı.
4. `bootloader_control`'ün CRC'si doğrulanmıyor; magic + version + 3-bit alan sınırı
   yeterli mi, gerçek bir cihazda görülecek.
5. `misc_block_device` neverallow'ındaki `hal_boot_default` adı hedefin AOSP sürümündeki
   boot control HAL domain'iyle uyuşuyor mu (HIDL yerine AIDL ise ad farklı olabilir).

### G.3 Tasarımın çıkışı olmayan köşesi

Recovery gate bunu gizlemiyor, **isimlendiriyor**:

> Vault kullanılamıyor **ve** ağ sinyalleri temiz değil → otomatik çare yok.

Bu durumda gate, az önce reddettiği indirmeyi denemiyor. Denemek, motorun tam olarak
reddettiği şeyi yapmak olur. `sys.xrom.recovery.outcome=no-remedy` yazıp duruyor ve
operatör müdahalesi istiyor. Boot-loop guard'ın karşılığı da aynı: recovery denemeleri
tükenmiş ve başka bootable slot yoksa `kNone` döner — ama **sebebiyle**, çünkü her iki
çarenin de değerlendirilip reddedildiğini gizlemek operatörün bilmesi gereken tek şeyi
gizlemek.

### G.4 Geliştirme anahtarları

`security/ota_trust/ota_trust_anchors.json` içindeki iki anchor **geliştirme anahtarı** ve
ikisi de `enabled: true`. Sebebi: enabled anchor'ı olmayan bir build hiçbir şey
kuramaz ve bu, gerçek anahtarı olmayan bir release build için *doğru* durum — ama
bring-up için kullanılabilir bir durum değil.

`xrom_preflight.py` bunu **uyarı** olarak bildiriyor (hata değil, çünkü bring-up'ta
doğru durum). Release image'ından önce ikisi de üretim anahtarlarıyla değiştirilmeli.

Private yarımlar bu depoda **yok**; sadece public yarımlar commit edildi ve
`.gitignore`'daki `*.pem` kuralı private'ları yakalamaya devam ediyor (iki yönde de
doğrulandı: public'ler stage oluyor, private bir probe ignore ediliyor).

Aynı durum Session 2'nin payload anchor'ları için de geçerli ve orada da değişmedi.

### G.5 Bilinçli olarak eklenmeyenler

- **`REMOTE_ATTESTED`** — kısıt gereği eklenmedi. RKP ağ gerektirir ve vsock-only
  hardening ile çelişir. `AttestationLevel::kRemoteAttested` enum'da duruyor ama
  shipped konfigürasyonda **erişilemez** ve bu `docs/04` §C.3'te de aynı şekilde yazılı.
- **X-Defender entegrasyonu** — sonraki oturum. `CONFIG_BPF_SYSCALL` o zamana kadar
  kapalı; yeniden açıldığında imzalı, ölçülmüş bir BPF object'i ve bir loader
  allowlist'i ile birlikte açılmalı.
- **Elle yazılmış SHA-256 / imza / MAC** — hiçbir yerde yok. SHA-256 yayınlanmış
  vektörlerle doğrulanmış; imzalar BoringSSL ile.

---

## Değiştirilen ve eklenen dosyalar

```
common/recovery/          BcbMessage, RecoveryDecision, QuarantinePlan,
                          VaultMetadata, BootAttemptPolicy  (+ Android.bp, 5 test)
common/ota/               OtaManifest, OtaVerifier          (+ Android.bp, 2 test)
aidl/android/xrom/recovery/   IXRecoveryService + 7 parcelable/enum
services/recovery/xrom_sentineld/   SentinelConfig, PlatformActions, NetdCompat,
                                    SentinelService, main, Android.bp, config, rc
services/ota/xrom_ota_installer/    OtaTrust, main, Android.bp
bootable/xrom_recovery_gate/        main, Android.bp
security/ota_trust/       ota_trust_anchors.json + public anahtarlar
sepolicy/                 2 yeni domain (public + private), xrom_vault_device,
                          xrom_vault_meta_device, xrom_sentinel_data_file,
                          xrom_ota_trust_file, xrom_recovery_service,
                          xrom_recovery_prop
device/x1/                BoardConfig (vault partition + AVB), recovery.fstab,
                          recovery.mk, init.xrom.sentinel.rc, device.mk
tools/                    xrom_sign_ota.py, xrom_verify_ota.py,
                          tests/ota_signing_roundtrip.sh,
                          xrom_preflight.py (+7 grup), run_host_tests.sh (+2 suite)
```
