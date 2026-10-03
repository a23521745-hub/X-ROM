# Oturum 2 — Vsock veri düzlemi, payload imzalama ve çıktı doğrulama

Bu belge Oturum 1'in (`docs/01`, `docs/02`, `docs/03`) üzerine eklenen üç bileşeni
anlatıyor: host ile pVM arasında çift yönlü veri akışı, Microdroid içinde çalışan
paketlerin imza/ölçüm doğrulaması ve dönen sonucun kriptografik olarak kanıtlanabilir
olması.

Oturum 1'de VM boot ediyordu ama içine giren ve içinden çıkan hiçbir bayt yoktu.
`IsolationService.cpp` içinde `result.outputDigest = {}` satırı ve üzerinde
"SESSION 1 SCOPE" yazan bir yorum duruyordu. Bu oturum o satırı kaldırdı.

---

## Bölüm A — Vsock veri düzlemi

### A.1 Sıralama güvenlik argümanının kendisi

El sıkışma şu sırayla çalışıyor ve bu sıra değiştirilebilir bir ayrıntı değil:

```
  guest                                          host
    │                                              │
    │  1. ortamı doğrula (SELinux enforcing,       │
    │     root değil)                              │
    │  2. kendini ölç (/proc/self/exe,             │
    │     vm_config.json, apk contents)            │
    │  3. vsock 7100'de bind + listen              │
    │  4. AVmPayload_notifyPayloadReady()  ───────►│  onPayloadReady
    │                                              │  5. connectVsock(7100)
    │◄─────────────────────────────────────────────│
    │  6. kGuestHello (ölçümler)  ────────────────►│  7. imzalı manifest ile
    │                                              │     karşılaştır
    │                                    eşleşmezse│  8. kTaskAbort
    │                                              │     (kMeasurementRejected)
    │◄────  9. kTaskBegin (nonce, input_digest,  ──│     eşleşirse
    │           task_class, authorization_level)   │
    │◄──── 10. kTaskInput × N                      │
    │◄──── 11. kTaskInputEnd                       │
    │ 12. input_digest'i yeniden hesapla           │
    │     ve kTaskBegin'deki ile karşılaştır       │
    │ 13. işi yap                                  │
    │───── 14. kTaskOutput × N  ──────────────────►│ 15. biriktir, hashle
    │───── 16. kTaskResult      ──────────────────►│ 17. nonce + output_digest
    │        (nonce echo, output_digest,           │     + ölçümleri doğrula
    │         instance_binding, ölçümler)          │
```

Kritik olan **6. adımın 9. adımdan önce gelmesi**. Host, guest kendini tanıtmadan
ve o tanım imzalı manifest ile eşleşmeden tek bir bayt görev girdisi göndermiyor.
Tersi sırada — önce girdi, sonra kimlik — doğrulama bir kapı olmaktan çıkıp bir
rapora dönüşürdü: girdi çoktan verilmiş olurdu.

`AVmPayload_notifyPayloadReady()` çağrısının **bind+listen'den sonra** gelmesi de
aynı sebepten. Host bu sinyali "bağlanabilirim" diye yorumluyor. Dinleyici
kurulmadan önce gönderilirse, host'un `connectVsock`'u hiçbir şey dinlemeyen bir
porta bağlanmaya çalışır ve hata "VM bozuk" gibi görünür — aslında yarış
durumudur. `VmLifecycleObserver::WaitForPayloadReady()` bu yüzden eklendi;
Oturum 1'de bilinçli olarak `WaitForPayloadLaunched` kullanılıyordu çünkü o
zamanki payload hiç `notifyPayloadReady` çağırmıyordu.

### A.2 Çerçeve biçimi

`common/protocol/VsockProtocol.h` tek sözleşme noktası. Her yapı `__attribute__((packed))`,
`alignof == 1` ve boyutu `static_assert` ile sabitlenmiş:

| Yapı | Boyut | Yön |
|---|---|---|
| `FrameHeader` | 48 | her iki yön |
| `GuestHelloPayload` | 100 | guest → host |
| `TaskBeginPayload` | 140 | host → guest |
| `TaskResultPayload` | 176 | guest → host |
| `TaskAbortPayload` | 68 | her iki yön |

Başlık: `magic 0x4D4F5258` ("XROM", little-endian), `version 1`, `type`,
`payload_length` ve **payload'ın SHA-256'sı**. Sindirim başlıkta taşımanın sebebi
var: bir çerçevenin gövdesi, çerçevenin kendisi doğrulanmadan yorumlanmıyor.
`magic` ise akış senkronu kaybolduğunda ilk takılınan şey — bu yüzden her şeyden
önce o kontrol ediliyor.

Tavanlar: çerçeve gövdesi 4 MiB, girdi 16 MiB, çıktı 16 MiB, `task_id` 64 bayt,
abort ayrıntısı 64 bayt, nonce 32 bayt.

### A.3 Kodlayıcı ve çözücü aynı kuralları uyguluyor

Bu, testlerin bulduğu gerçek bir hataydı ve düzeltildi:

* `EncodeTaskBegin` boş `task_id` kabul ediyordu, `DecodeTaskBegin` reddediyordu.
  Sonuç: host'un gönderdiği çerçeveyi guest sessizce düşürüyor, hata "transport
  sorunu" gibi görünüyordu. Kodlayıcı artık aynı reddi uyguluyor.
* `ToFixedBuffer` içine gömülü NUL içeren bir diziyi kabul ediyordu;
  `FromFixedBuffer` ilk NUL'a kadar okuyup gerisinin sıfır olmasını istediği için
  `"ab\0cd"` guest tarafında `"ab"` oluyordu. İki taraf aynı görev kimliği
  konusunda anlaşmadan farklı değerler görüyordu. Artık gömülü NUL reddediliyor.
* `EncodeTaskAbort` sebebi doğrulamıyordu, `DecodeTaskAbort` doğruluyordu.
  Üçüncü bir `AbortReason` eklendiğinde (`kTaskClassNotAllowed`, `kInputTooLarge`,
  `kNoAuthorization`) çözücünün `switch`'i güncellenmemişti — yani guest'in
  gönderdiği yeni sebepler host tarafından okunamıyordu. İki taraf artık ortak
  `IsKnownAbortReason()` fonksiyonunu çağırıyor.
* `DecodeHeader` bildirilen gövdenin tampona sığıp sığmadığını **bilerek**
  kontrol etmiyor: akış okuyucusu başlığı, ne kadar daha okuyacağını bilmeden
  önce ayrıştırır. Bu doğru ama tehlikeli, o yüzden tamponun tamamını doğrulayan
  `DecodeFrame()` eklendi.

`tools/xrom_preflight.py` içindeki `protocol wire layout` grubu bu sınıf hataları
statik olarak yakalıyor: her `FrameType`/`AbortReason`/`AttestationLevel`
numaratörünün `IsKnown*` ve `*Name` fonksiyonlarında geçtiğini kontrol ediyor.
Yeni bir sebep ekleyip çözücüyü güncellememek artık derleme değil **preflight**
hatası.

### A.4 Kanal: `common/vsock/VsockChannel`

`VsockChannel` bir dosya tanımlayıcısını tam, sindirimi doğrulanmış çerçevelere
çeviriyor. **Binder, libbase, log veya AIDL içermiyor** — saf POSIX (`poll`,
`send`, `recv`). Bu bir tercih değil, test edilebilirliğin koşulu:

> Veri düzleminin testleri `AF_UNIX` `socketpair` üzerinde çalışıyor. Bir bayt
> bayt damlatılan 5000 baytlık bir çerçeve, bozulmuş bir gövde baytı, bozuk
> magic, yarıda kesilmiş çerçeve, temiz kapanma, zaman aşımı, bütçe aşımı ve
> çerçeve limiti — hepsi hipervizör, cihaz veya guest imajı olmadan
> çalıştırılıyor. Yalnızca gerçek bir pVM'e karşı test edilebilen bir transport,
> hata yolları hiç çalıştırılmamış bir transport demektir.

Aynı sınıfı iki taraf da kullanıyor: host `IVirtualMachine::connectVsock(port)`
ile, guest `accept4(AF_VSOCK)` ile bir fd alıyor ve `AdoptFd()` ile kanala
veriyor.

Kanalın tipli alıcı/göndericileri var (`SendTaskBegin`, `ReceiveGuestHello`, …).
Bunların sebebi test sırasında bulunan gerçek bir karışıklık: `EncodeTaskBegin`
**tam bir çerçeve** döndürüyor, `SendFrame` ise **payload** bekliyor. Birini
ötekine verirseniz çerçeve çerçeve içine giriyor — sindirim doğrulanıyor,
aktarım başarılı görünüyor, uzak taraf iç baytları çözemiyor ve hata guest'te
bir bozukluk gibi görünüyor. `SendEncodedFrame` yazmadan önce `DecodeFrame` ile
doğruluyor, yani bu hata artık temsil edilemez.

### A.5 Sınırlar: kötü niyetli guest ne yapabilir

Guest uzlaşmış olabilir. Her "her şey" bir maliyet tavanına bağlanmış durumda:

| Saldırı | Karşı önlem |
|---|---|
| Dev çerçeve bildirip host'u allocate ettirmek | `DecodeHeader` tavanı kontrol ediyor; allocation **doğrulanmış** bir uzunluktan sonra |
| Çıktıyı sonsuz akıtmak | `SetReceiveBudget` — kanal ömrü boyunca kabul edilen toplam bayt; aşımda birikim **hiç başlamıyor** |
| Milyonlarca küçük çerçeve | `SetMaxFrames` |
| Gövdede tek bayt bozma | `VerifyPayloadDigest` — çerçeve reddediliyor, yarı çözülmüş bayt bırakılmıyor |
| Yanlış tip çerçeve | `ReceiveTyped` beklenen tipi kontrol ediyor |
| Sonuç yerine başka bir görevin sonucu | nonce echo karşılaştırması |
| Host'a CID 2 dışında birinden bağlanmak | guest `accept4` sonrası `peer.svm_cid == kHostCid` kontrolü yapıyor |

### A.6 Vsock neden tek çıkış yolu

Bu özellik payload'ın işbirliğine dayanmıyor; üç ayrı yerde, birbirinden
bağımsız olarak zorlanıyor:

1. **`assets/vm_config.json` içinde `"network": true` yok.** Microdroid
   payload'a hiçbir ağ arayüzü vermiyor. Bağlanılacak bir şey yok.
2. **`sepolicy/microdroid/xrom_microdroid_hardening.te` içinde neverallow
   kuralları.** `packet_socket`, `rawip_socket`, `tcp_socket`, `udp_socket`,
   `sctp_socket`, `dccp_socket`, jenerik `socket` sınıfı ve 16 netlink ailesi.
3. **Microdroid linker namespace'i payload'a NDK kütüphane kümesini açıyor.**
   `getaddrinfo` yok, `libssl` yok, HTTP istemcisi yok.

İkinci maddenin bir yan etkisi bilinçli olarak kabul edildi ve politika
dosyasında uzun uzun yazıldı: `RELEASE_AVF_ENABLE_NETWORK` açık bir derlemede
AOSP'nin Microdroid politikası `microdroid_payload`'a tcp/udp **allow** veriyor,
yani bu neverallow'lar canlı bir allow ile çelişip SELinux derlemesini kırıyor.
**Bu kırılma istenen davranış.** X-ROM'un izolasyon garantisi vsock-only çıkış
gerektiriyor; payload ağını açan bir derleme durup karar vermek zorunda. Düzeltme
`RELEASE_AVF_ENABLE_NETWORK := false`, kuralların silinmesi değil.

Dört netlink ailesi (`netlink_socket`, `netlink_kobject_uevent_socket`,
`netlink_selinux_socket`, `netlink_audit_socket`) bilerek listede yok: temel
politika bunları koşulsuz veriyor, yani neverallow gerçek bir delik kapatmadan
derlemeyi kırardı. Payload'ın kendi enforcing durumunu okuması
`netlink_selinux_socket` gerektiriyor.

---

## Bölüm B — Payload imzalama

### B.1 AVF zaten doğruluyor; neden yetmiyor

AVF'nin yaptığı doğrulama gerçek: pvmfw, APK'nın fs-verity sindirim ağacını
(`.idsig`) kontrol ediyor ve bunu VM kimliğine ölçüyor; bütün zincir AVB'ye
bağlı. Ama bu "bu APK kurcalanmış mı?" sorusunu cevaplıyor, **"bu APK'yı X-ROM mu
seçti?"** sorusunu cevaplamıyor.

Kendi derlediğiniz bir ROM'da payload APK'sı **platform sertifikası** ile
imzalanıyor — sistemdeki her bileşenle aynı anahtar. Yani aynı ağaçta derlenmiş,
aynı anahtarla imzalanmış, aynı partition'a kurulmuş bir payload AVF altında
kusursuz doğrulanır; X-ROM'un göndermeyi hiç düşünmediği bir payload dahil.

Manifest ikinci, bağımsız bir güven çapası ekliyor: platform anahtarı olmayan bir
X-ROM imza anahtarı ve APK'nın tam baytlarının sabitlenmiş SHA-256'sı.

### B.2 Doğrulanması gereken dört ayrı şey

`PayloadVerifier::Verify()` şu dördünün **hepsi** doğruysa geçiyor:

1. Manifestin ayrık imzası, `trust_anchors.json` içinde **key_id ile sabitlenmiş**
   bir anahtarla doğrulanıyor. Anahtarın id ile seçilmesi (her çapayı deneyip
   doğrulayanı bulmak yerine) şu demek: trust dizinine yazabilen bir saldırgan,
   kendi anahtarını ekleyerek onu yetkili kılamaz. Ayrıca algoritma da eşleşmek
   zorunda — bir manifest Ed25519 çapasını daha zayıf bir şemaya düşüremez.
2. Manifest `PayloadManifest::Validate()`'i geçiyor: sürüm, ad, geçerlilik
   penceresi, algoritma, sıfır olmayan sindirimler, boş olmayan görev sınıfı
   listesi, yol ayıracı içermeyen dosya adları.
3. `security_version` çapanın `min_security_version` değerinden düşük değil.
   Geçerli imzalı ama eskimiş bir manifest, bir güvenlik düzeltmesinden sonra
   yeniden oynatılamaz.
4. Diskteki APK'nın SHA-256'sı sabitlenmiş `apk_sha256` ile eşleşiyor. Bu
   **çalışma zamanında**, daemon'un AVF'ye vermek üzere olduğu baytlar üzerinde
   yeniden hesaplanıyor.

Bunların dördü de `AvfController::StartVm()`'den **önce**, hatta
`EnsureIdsig()`'den önce çalışıyor. Reddedilen bir payload pvmfw'e hiç
ulaşmıyor, VM allocation almıyor ve `/dev/kvm`'e dokunmuyor.
`xrom_preflight.py`'daki `data plane wiring` grubu bu sıralamayı statik olarak
kontrol ediyor — doğrulama bloğunu `StartVm`'in altına taşımak preflight hatası.

### B.3 İmza neden ayrık (detached)

`xrom_payload_manifest.json.sig`, `xrom_payload_manifest.json`'ın **tam
baytlarını** imzalıyor. Kanonikleştirme adımı yok, dolayısıyla imzalama aracı ile
doğrulayıcının üzerinde anlaşmazlığa düşebileceği bir serileştirme de yok. Bir
JSON kanonikleştirme şeması (JCS, sıralı anahtar yeniden kodlaması) bir güvenlik
kararının iki tarafına iki bağımsız serileştirici koyardı ve aralarındaki fark
saldırı yüzeyi olurdu.

### B.4 Desteklenen iki şema

| Şema | İmza boyutu | Neden |
|---|---|---|
| `ED25519` | 64 bayt | Hızlı, küçük, anahtar 44 bayt SPKI. Varsayılan. |
| `RSA4096_SHA256` | 512 bayt | Ed25519 anahtarı dışa aktaramayan HSM ortamları için. |

İkisi de BoringSSL ile doğrulanıyor (`EVP_DigestVerifyInit` /
`EVP_DigestVerify`). Ed25519 için `EVP_MD` argümanı NULL olmak zorunda ve yalnızca
tek-atımlı biçim kullanılabiliyor; RSA için `EVP_sha256()` ile RSASSA-PKCS1-v1_5.
**X-ROM hiçbir yerde bir imza şemasını kendisi uygulamıyor.** Uygulanan tek
kriptografik primitif SHA-256 (`common/crypto/Sha256.cpp`) ve o da yayınlanmış
NIST vektörlerine ve `openssl dgst -sha256` çıktısına bayt bayt doğrulanmış
durumda.

SHA-256'nın kendisinin yazılmasının sebebi var: **guest BoringSSL
linkleyemiyor.** Microdroid linker namespace'i payload'a NDK kümesini açıyor ve
`libcrypto` onun parçası değil. Aynı sindirimin birbirinden sapabilen iki
uygulaması, bağımsız tek bir uygulamadan daha kötü, o yüzden iki taraf da aynı
bağımlılıksız kodu kullanıyor.

### B.5 Güven materyali

```
security/payload_trust/
├── Android.bp                     prebuilt_etc → /system_ext/etc/xrom/trust/
├── trust_anchors.json             sabitlenmiş GENEL anahtarlar (commit edilir)
├── keys/*.pub.pem                 genel yarımlar (commit edilir)
└── manifest/README.md             sürüm komutları
```

Kurulum yolu `/system_ext/etc/xrom/trust/`. Üç yerin aynı yolu söylemesi
gerekiyor ve preflight bunu kontrol ediyor: `VmSpec.h` içindeki
`kPayloadTrustRoot`, `file_contexts` içindeki etiket ve `Android.bp` içindeki
`sub_dir`. SELinux tarafında yeni bir tip var — `xrom_payload_trust_file` — ve
`xrom_avfd_config_file`'dan bilerek ayrı: bozuk bir `avf.json` daemon'u
derlenmiş güvenli varsayılanlara düşürür, bozuk bir trust dosyası ise **her şeyi
reddetmek** zorunda. Çalışma zamanında hiçbir domain bu dizine yazamıyor, ve
daemon dışında hiçbir domain okuyamıyor.

**Özel anahtarlar ağaçta yok.** `tools/tests/payload_signing_roundtrip.sh` bunu
mekanik olarak kontrol ediyor (`security/` altında `*.pub.pem` olmayan bir `.pem`
veya içeriğinde `PRIVATE KEY` geçen herhangi bir dosya = test hatası). Commit
edilen geliştirme çapaları gerçek anahtarlardan üretildi; özel yarımları geçici
bir dizinde üretildi ve atıldı.

### B.6 Manifest bir sürüm artefaktı, kaynak dosya değil

Manifest, derlenmiş APK'nın ve `.so`'nun SHA-256'sını sabitliyor. Bu dosyalar
derleme çalışana kadar var olmadıkları için manifest kaynak ağacına konamaz.
Dolayısıyla **imzalanmamış bir checkout'ta daemon fail-closed**: her görevi
reddediyor ve nedenini söylüyor. Bu bir eksik değil, doğru durum.

```sh
./tools/xrom_sign_payload.py generate-keys --out-dir /secure/xrom-keys
m XVaultPayload libxvault_payload
./tools/xrom_sign_payload.py sign --apk ... --payload-lib ... --vm-config ... \
    --key /secure/xrom-keys/xrom-payload-ed25519.pem --key-id xrom-payload-root-01 \
    --task-classes 0,1 --security-version 1 --out-dir security/payload_trust/manifest
./tools/xrom_sign_payload.py anchor --key ... --key-id xrom-payload-root-01 \
    --min-security-version 1 --out security/payload_trust/trust_anchors.json
./tools/xrom_verify_manifest.py --manifest ... --signature ... --anchors ... --apk ...
```

Araçlar asimetrik işlemler için `openssl` CLI'ını çağırıyor, sindirimler için
stdlib `hashlib`. Python'ın `cryptography` paketi bir Android ağacının derleme
bağımlılığı değil; `openssl` ise zaten var.

`payload_lib_sha256` derlenmiş `.so` üzerinden hesaplanıyor ve guest
`/proc/self/exe`'yi ölçüyor. `use_embedded_native_libs: true` ile APK içindeki
kütüphane sıkıştırılmadan ve sayfa hizalı saklandığı için çıkarılan baytlar
derlenen baytlarla aynı — iki ölçüm bu yüzden karşılaştırılabilir.

---

## Bölüm C — `outputDigest` ve çıktının doğrulanması

### C.1 Host'un yeniden hesapladığı şey

`IsolationService::RunDataExchange()` bir sonucu yalnızca şunların **hepsi**
doğruysa kabul ediyor:

1. Her `kTaskOutput` çerçevesinin sindirimi kanal tarafından doğrulandı (yani
   biriken baytlar gelen baytlar).
2. Host'un biriktirdiği baytlar üzerinden hesapladığı SHA-256, guest'in
   `kTaskResult` içinde bildirdiği `output_digest` ile eşleşiyor.
3. `output_length` gerçekten alınan bayt sayısına eşit.
4. `exit_code == 0`.
5. **Nonce echo** bu görev için üretilmiş nonce ile eşleşiyor. Başka bir görevin
   nonce'unu taşıyan sonuç ya bir yeniden oynatmadır ya da `kTaskBegin`'i yok
   sayan bir payload'dır; ikisi de başarı olarak rapor edilemez.
6. Sonuçla birlikte **yeniden gönderilen** `payload_lib_digest` ve
   `vm_config_digest`, manifest'te sabitlenmiş değerlerle ve `kGuestHello`'daki
   değerlerle eşleşiyor.

Nonce `RAND_bytes` ile üretiliyor — libcrypto zaten linkli, CSPRNG ve bir dosya
tanımlayıcısı ya da SELinux izni gerektirmiyor.

### C.2 Sonuç neden tek başına yeterli değil

`SUCCEEDED` durumu **hem** veri düzleminin **hem** VM yaşam döngüsünün görevin
çalıştığını söylemesini gerektiriyor. İkisi çelişebilir: doğrulanmış bir çıktının
ardından VM ölebilir, ya da VM hiç sonuç göndermeden 0 ile çıkabilir. Birinci
durumda çıktı, çökmenin bozmuş olabileceği bir durumla üretilmiş olabilir;
ikincide 0 ile biten bir süreç yalnızca bitmiş bir süreçtir.

`IsolationTaskResult` bu yüzden genişletildi (`frozen: false`, dolayısıyla alan
eklemek ABI'ı kırmıyor):

| Alan | Anlamı |
|---|---|
| `outputDigest` | Guest'in bildirdiği ve host'un yeniden hesapladığı çıktı SHA-256'sı |
| `attestationLevel` | Sonucun neyle desteklendiği (aşağıda) |
| `outputLength` | Gönderilen çıktı bayt sayısı |
| `payloadLibDigest` | VM içinde ölçülmüş payload kütüphanesi |
| `vmConfigDigest` | VM içinde ölçülmüş `vm_config.json` |
| `apkContentsDigest` | Guest'in hesapladığı, açılmış APK dizini sindirimi |
| `instanceBinding` | Yalnızca bu VM instance'ının üretebildiği bağ |
| `nonce` | Host'un ürettiği ve guest'in geri gönderdiği nonce |
| `payloadName`, `manifestKeyId`, `manifestSecurityVersion` | Hangi manifest bunu yetkilendirdi |

Sindirim alanları **boş bırakılıyor**, sıfırla doldurulmuyor: boş "doğrulanmış
çıktı yok" demek, sıfırlar ise "sıfıra hash'lenen bir çıktı var" demek olurdu ve
ikisi aynı görünürdü.

### C.3 Üç seviye — ve hangisi gerçekten neyi kanıtlıyor

Bu bölüm abartmamak için yazıldı. "VM bunu üretti" tek bir özellik değil, üç
farklı özellik ve güçleri çok farklı.

**`MEASUREMENT_ONLY` (0).** Host, APK ve kütüphane sindirimini imzalı manifestte
sabitledi; guest aynı artefaktları VM'in içinden bağımsız olarak ölçtü ve eşleşti.
pKVM + pvmfw + X-ROM manifestinin verdiği şey bu ve **her zaman mevcut**. Elediği
şey ikame edilmiş bir payload: guest'in çalıştırdığı baytlar X-ROM'un imzaladığı
baytlar. Elemediği şey dürüst olmayan bir host — ölçümlerin sonuçla birlikte
yeniden gönderilmesinin sebebi bu.

**`INSTANCE_BOUND` (1).** Ek olarak `AVmPayload_getVmInstanceSecret()`'dan gelen
bir gizli karıştırılmış: cihaz-özel bir hipervizör değerinden, payload kodundan ve
değiştirilemeyen yapılandırmadan türetiliyor; VM kimliği değişmediği sürece
stop/restart/reboot arasında kararlı; **host'a ve başka hiçbir VM'e açık değil.**
Aldığı şey: bir `kTaskResult` çerçevesi VM instance'ları arasında taşınabilir
değil ve payload boot'lar arası bir yeniden oynatmayı kendisi tespit edebilir.
**Host bunu doğrulayamaz** — gizliye erişimi yok. Bunu kanıt diye sunmak yalan
olurdu.

**`REMOTE_ATTESTED` (2).** Ek olarak `AVmPayload_requestAttestation()`: leaf
sertifikasında challenge ve payload'ın `codeHash`'ini taşıyan bir RKP sertifika
zinciri ve yalnızca o pVM'in sahip olduğu bir anahtarla atılmış ECDSA P-256
imzası. **Origin'i host'a kriptografik olarak kanıtlayan tek seviye bu.**

Ve X-ROM'un gönderilen yapılandırmasında **erişilemez**, çünkü:

> Uzaktan attestasyon RKP servisini gerektirir → RKP ağ erişimini gerektirir →
> X-ROM'un Microdroid payload'ları vsock-only çıkışa sertleştirilmiş durumda
> (Bölüm A.6).

Bu bir çelişki ve gizlenmiyor. Cihazın erişemediği bir seviyeyi raporlamak,
enum'un hiç olmamasından daha kötü olurdu; bu yüzden dürüst tavan
`INSTANCE_BOUND`. Kod bu seviyeyi **istemiyor** bile; `AttestationLevel.aidl`
içinde, `VsockProtocol.h` içinde ve payload'ın `ComputeInstanceBinding()`
fonksiyonunun başında aynı gerekçe yazılı.

### C.4 Host seviyeyi düşürebilir, yükseltemez

Guest bir seviye **bildirir**; host yalnızca **destekleyebildiğini** iddia eder.
`RunDataExchange` içindeki mantık:

* Host her zaman `MEASUREMENT_ONLY`'yi destekleyebilir — az önce yaptı.
* `INSTANCE_BOUND` ek olarak sıfır olmayan bir binding gerektiriyor. Host onu
  yeniden hesaplayamadığı için kontrol "guest gerçekten bir tane üretti mi".
* `REMOTE_ATTESTED` host'un doğruladığı bir sertifika zinciri gerektirir;
  protokol bunu taşımıyor. Guest bunu iddia ederse host bir `WARNING` yazıyor ve
  `INSTANCE_BOUND` raporluyor.

### C.5 Politika ile manifestin kesişimi

İki kapı var ve farklı şeylere bakıyorlar:

* `IsolationPolicy::Evaluate()` — **bu çağıran** bu sınıfı isteyebilir mi?
* `IsolationPolicy::EvaluatePayloadTrust()` — **bu payload** o sınıfı yapmaya
  yetkili mi?

İkisinin de evet demesi gerekiyor. Ayrı olmalarının sebebi ayrı sebeplerle
başarısız olmaları: bir manifest meşru olarak yalnızca `STATIC_ANALYSIS` için
imzalanmış olabilir, politika ise çağıranın `CRYPTO_OPERATION` istemesine izin
veriyor olabilir. Bu kombinasyonun doğru cevabı "bu payload ile olmaz" — "isteme
hakkın yok" değil.

`EvaluatePayloadTrust` ayrıca manifestin adlandırdığı kütüphane ile o sınıf için
politikanın adlandırdığı kütüphanenin aynı olmasını kontrol ediyor; yoksa imzalı
manifest, gerçekte çalışacak olandan farklı bir binary'i yetkilendiriyor olur.

Referans payload kendi tarafında da bir liste tutuyor (`kServedTaskClasses =
{0, 1}`) ve host'tan gelmeyen bu liste dışında bir sınıf isterse
`kTaskClassNotAllowed` ile reddediyor. Birbirinden bağımsız iki kontrolün
çelişmesi bir sinyaldir; tek kontrol tek bir hata noktasıdır.

---

## Bölüm D — Testler ve doğrulama

### D.1 Aynı iddialar, iki çalıştırıcı

`common/` ve `libxrom_avf_core` altındaki her şey bağımlılıksız, dolayısıyla hem
ağaç içinde `cc_test` hem de ağaç dışında sistem `g++` ile derleniyor — **aynı
`.cpp` dosyaları**:

```sh
tools/hostcheck/run_host_tests.sh          # AOSP yok, cihaz yok, Soong yok
atest xrom_shared_core_test                # ağaç içinde
atest xrom_avf_core_test
```

| Suite | Kapsam |
|---|---|
| `xrom_avf_core_test` | `VmSpec`, `IsolationPolicy`, `PayloadManifest` — 50 test / 182 kontrol |
| `xrom_shared_core_test` | SHA-256, wire codec, vsock transport — 49 test / 274 kontrol |

`tools/xrom_preflight.py` içindeki `host tests are wired` grubu, eklenen her
`*_test.cpp` dosyasının **hem** kendi `Android.bp`'sinde **hem**
`run_host_tests.sh` içinde listelenmesini zorunlu kılıyor. Tek bir yerde listelenen
bir test, bir yerde hiç çalışmayan bir testtir.

### D.2 İmzalama hattı uçtan uca

```sh
tools/tests/payload_signing_roundtrip.sh   # 34 iddia
```

Geçici bir dizinde anahtar üretiyor (özel anahtar asla commit edilmiyor), iki
şemayla da imzalıyor, doğruluyor ve sonra **her kurcalama vakasını** tek tek
test ediyor: değiştirilmiş manifest, değiştirilmiş APK, kırpılmış imza, bilinmeyen
anahtarla imzalanmış manifest, süresi dolmuş manifest, yükseltilmiş
`min_security_version` (anti-rollback), devre dışı çapa, boş görev sınıfı listesi,
bilinmeyen görev sınıfı, 2048 bitlik RSA anahtarı. Ayrıca commit edilmiş
`trust_anchors.json`'ın her çapasının DER'inin beyan edilen türle eşleştiğini
doğruluyor.

Bu, `PayloadVerifier.cpp`'yi test etmiyor — o BoringSSL istiyor ve ağaç içinde
çalışıyor. Test ettiği şey, C++ doğrulayıcının alacağı artefaktların doğru
biçimlendiği ve şemanın kendi içinde tutarlı olduğu. `xrom_verify_manifest.py`
aynı kuralların ikinci bir uygulaması: ikisi anlaştığında cihazdaki bir hata
cihazın durumuna işaret eder; anlaşmadıklarında birinde hata vardır ve bu
okunması kolay olanıdır.

### D.3 Statik kontrol

```sh
python3 tools/xrom_preflight.py    # 22 grup, 0 hata, 1 uyarı
```

Oturum 2'de eklenen yedi grup: `shared code is dependency free`,
`protocol wire layout`, `payload egress is vsock only`,
`payload trust material`, `data plane wiring`, `host tests are wired`,
`payload signing tools`.

Tek beklenen uyarı: `no signed payload manifest in security/payload_trust/manifest/`.
Bu bir ağaç hatası değil, imzalanmamış bir checkout'ın doğru durumu.

Linter'ın kendisi de negatif test edildi. Sekiz kasıtlı regresyon enjekte edildi
ve **sekizi de yakalandı**, sonra geri alındı:

| # | Enjekte edilen hata | Yakalayan grup |
|---|---|---|
| 1 | `common/vsock`'a `<android-base/logging.h>` eklemek | shared code is dependency free |
| 2 | `neverallow self:tcp_socket` satırını silmek | payload egress is vsock only |
| 3 | `vm_config.json`'a `"network": true` | payload egress is vsock only |
| 4 | `security/` altına özel anahtar koymak | payload trust material |
| 5 | Doğrulamayı `StartVm`'in altına taşımak | data plane wiring |
| 6 | Payload'da `notifyPayloadReady`'yi `listen`'den önceye almak | data plane wiring |
| 7 | Çözücüye öğretilmemiş yeni bir `AbortReason` | protocol wire layout |
| 8 | Runner'lara bağlanmamış bir `*_test.cpp` | host tests are wired |

### D.4 Cihaz üzerinde

```sh
tools/xrom_avf_verify.sh    # 12 bölüm
```

Oturum 2'de eklenen üç bölüm: **9** trust materyalinin kurulu ve doğru
etiketli olduğunu, **10** cihazdaki manifesti cihazdaki APK'ya karşı çekip
doğruladığını (imzanın farklı bir derlemenin APK'sı üzerinde atılması vakasını
yakalayan kontrol bu), **11** log tamponunda veri düzleminin gerçekten
çalıştığına dair kanıt satırlarını aradığını ve asla görünmemesi gereken beş
satırı kontrol ettiğini doğruluyor.

---

## Bölüm E — Bilinen sınırlar

Dürüst olmak için yazıldı; bunlar unutulmuş değil, bilinçli olarak kabul edilmiş
sınırlar.

1. **Uzaktan attestasyon yok.** Bölüm C.3'te açıklandığı gibi vsock-only sertleştirme
   ile RKP aynı anda mümkün değil. Çözüm bir proxy olurdu: host'un RKP'ye
   erişebilen bir bileşeni, guest'in challenge'ını dışarı taşırdı — bu da
   Bölüm A.6'nın kapattığı ikinci kanalı geri açar. Bu oturumda yapılmadı.
2. **`PayloadVerifier.cpp` burada derlenmedi.** BoringSSL, libjsoncpp ve libbase
   gerektiriyor. Saf katman (`PayloadManifest`), codec ve transport derlendi ve
   test edildi; imza doğrulamasının kendisi ağaç içinde derlenecek.
3. **Guest payload stub başlıklarla derlendi.** `vm_payload.h` ve `log/log.h`
   olmadan, `-Wall -Wextra -Werror` altında hem Microdroid API'li hem API'siz
   yolda temiz. Gerçek derleme AOSP'te.
4. **`apkContentsDigest` zorlanmıyor, kaydediliyor.** Host, APK'yı açmadan aynı
   dizin sindirimini hesaplayamaz. Güven açısından zaten gereksiz — `apk_sha256`
   APK'nın tamamını host tarafında sabitliyor. Değeri, açılmış dizinin boot'tan
   sonra değiştirilmesini denetim izinde görünür kılması ve bir sonucu onu üreten
   dizin durumuna bağlaması.
5. **Manifest bir sürüm adımı.** `genrule` ile derlemeye bağlanmadı, çünkü imza
   derleme sandbox'ında bulunmaması gereken bir özel anahtar gerektiriyor.
   İmzalanmamış bir ağaç fail-closed; bu doğru davranış ama otomatik değil.
6. **Tek kontrol portu kullanılıyor.** `kPortTaskData` (7101) tanımlı ve
   ayrılmış ama bu oturumda kullanılmıyor; bütün akış 7100 üzerinde. Büyük
   girdi/çıktı için ikinci bir kanal ayırmak, kontrol kanalını veriyle
   tıkamamak demek — sıradaki oturumun işi.

### Sıradaki oturuma hazır bırakılan yüzeyler

* `common/vsock/VsockChannel` iki yönde de çalışıyor; ayrı bir veri kanalı
  eklemek yeni bir `VsockChannel` örneği demek, yeni bir transport değil.
* `AttestationLevel` enum'unun üçüncü seviyesi ayrılmış durumda. `kTaskAttestation`
  çerçeve tipi ve sertifika zinciri taşıma işi eklendiğinde, hem AIDL hem wire
  enum'u zaten doğru değeri taşıyor olacak.
* `PayloadVerifier`, `key_id` ile çapa seçtiği için anahtar rotasyonu yeni bir
  çapa eklemek + `min_security_version` yükseltmek; kod değişikliği gerekmiyor.
* `IsolationPolicy::EvaluatePayloadTrust` manifest'i parametre olarak alıyor,
  yani çoklu payload (farklı sınıflar için farklı imzalı APK'lar) desteği
  politikayı değil `VmSpec`'i değiştirmek demek.
