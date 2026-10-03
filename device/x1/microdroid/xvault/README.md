# X-Vault — Microdroid payload

pVM'in **içinde** çalışan izole güvenlik görevi. Host tarafındaki karşılığı
`services/avf/xrom_avfd`.

## Dosyalar

| Dosya | Ne |
|---|---|
| `payload/xvault_payload.cpp` | `AVmPayload_main`'i veren native kütüphane |
| `assets/vm_config.json` | Microdroid payload yapılandırması, APK'ya gömülür |
| `Android.bp` | `libxvault_payload` (cc_library_shared) + `XVaultPayload` (android_app) |
| `AndroidManifest.xml` | Uygulama olmayan bir uygulamanın manifesti |

## `vm_config.json` neden yorumsuz

Microdroid bu dosyayı `config_schema.xsd`'ye karşı **VM'in içinde** doğruluyor.
Bilinmeyen bir üst-düzey anahtar uyarı değil, açılış hatası — yani buraya
`_comment` koymak, payload'ı boot edilemez hâle getirir. Açıklama burada ve
`docs/01-avf-pkvm-foundation.md` §5'te.

Alanların anlamı:

```json
"os":   { "name": "microdroid" }          // Guest OS. "microdroid" dışındaki
                                          // değerler USE_CUSTOM_VIRTUAL_MACHINE
                                          // ve X-ROM'un ölçmediği bir imaj ister.
"task": { "type": "microdroid_launcher",  // dlopen + AVmPayload_main çağrısı
          "command": "libxvault_payload.so" }  // APK'nın gömülü jni kütüphanesi
"export_tombstones": true                 // Çökme dökümleri host'a aktarılsın.
                                          // Yalnızca debuggable VM'de anlamlı,
                                          // ama üretimde de zararsız.
```

`task.command` değeri, `Android.bp`'deki `cc_library_shared` modül adının `.so`
ekli hâli **ve** `jni_libs` listesinde bulunmak zorunda. Üçünün uyuşmaması
durumunda `microdroid_launcher` kütüphaneyi bulamaz;
`tools/xrom_preflight.py` bu üçünü çapraz kontrol ediyor.

## Host'un bu APK'yı nasıl gördüğü

```
/system_ext/app/XVaultPayload/XVaultPayload.apk
    jni/arm64-v8a/libxvault_payload.so     (sıkıştırılmamış, sayfaya hizalı)
    assets/vm_config.json
```

* Yol, `services/avf/xrom_avfd/VmSpec.h` içindeki `kPayloadApkRoot` /
  `kPayloadApkPath` sabitleriyle ve `sepolicy/system_ext_private/file_contexts`
  etiketiyle uyuşmak zorunda. Üçü de preflight'ta kontrol ediliyor.
* `use_embedded_native_libs: true` olmadan `.so` sıkıştırılır; o zaman
  Microdroid onu yazılabilir bir alana çıkarmak zorunda kalır ve doğrulanmış
  APK'dan doğrudan map'leme avantajı kaybolur.
* `certificate: "platform"` bir paketleme ayrıntısı değil: imza, `.idsig` digest
  ağacının bağlandığı şey ve o digest pvmfw tarafından VM kimliğine ölçülüyor.
  Anahtarı değiştirmek VM'in sırrını değiştirir.

## Oturum 1 kapsamı

Payload şu an: boot ediyor, guest ortamını doğruluyor (SELinux enforcing mi,
root değil mi, hangi ikili çalışıyor), logluyor ve 0 ile çıkıyor.

vsock veri düzlemi henüz bağlı değil. `common/protocol/VsockProtocol.h`
çerçeveleme sözleşmesini tanımlıyor ve payload protokol sürümü ile port
numaralarını logluyor, ama henüz bir çerçeve okumuyor ya da yazmıyor. Bu yüzden
host tarafında `SUCCEEDED` şu anlama geliyor: **"izole bir Microdroid pVM boot
etti ve ölçülmüş bir X-ROM payload'ı çalıştırdı"** — "çıktısı doğrulandı"
anlamına **gelmiyor**.

Payload içindeki kontroller neden var: pKVM host'un bu sürecin belleğini
okumasını engeller, ama host'un **dürüst** olmasını garanti etmez. VM'i host
yapılandırdı, bellek ve CPU sayılarını host seçti ve "girdi bu" diye bir dosya
tanımlayıcısını host verdi. "Doğrulayamadım" ile "doğrulandı" aynı cevap
olmamalı; bu yüzden bir kontrol başarısız olursa payload sıfır olmayan bir
kodla çıkıyor ve bu, `onPayloadFinished` üzerinden host'a FAILED olarak
ulaşıyor. Host bunu SUCCEEDED'a çeviremez.
