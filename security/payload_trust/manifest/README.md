# Payload manifest — sürüm artefaktı, kaynak dosya değil

Bu dizin derlemeden sonra dolmalıdır. `xrom_payload_manifest.json` ve
`xrom_payload_manifest.json.sig` imzalı payload manifestidir; `xrom_avfd` bunları
`PayloadVerifier::Verify()` içinde okur ve **doğrulama başarısız olursa hiçbir
pVM başlatılmaz**.

Manifest, derlenmiş APK'nın ve payload kütüphanesinin SHA-256 değerlerini sabitler.
Bu dosyalar derleme çalışana kadar var olmadıkları için manifest kaynak ağacına
konamaz; imzalama bir sürüm adımıdır.

## Üretim

```sh
# 1. Anahtarlar (bir kez, çevrimdışı makinede veya HSM'de)
./tools/xrom_sign_payload.py generate-keys --out-dir /secure/xrom-keys

# 2. Derleme
m XVaultPayload libxvault_payload

# 3. Manifesti imzala
./tools/xrom_sign_payload.py sign \
    --apk         out/target/product/x1/system_ext/app/XVaultPayload/XVaultPayload.apk \
    --payload-lib out/target/product/x1/obj/SHARED_LIBRARIES/libxvault_payload_intermediates/libxvault_payload.so \
    --vm-config   device/x1/microdroid/xvault/assets/vm_config.json \
    --key         /secure/xrom-keys/xrom-payload-ed25519.pem \
    --key-id      xrom-payload-root-01 \
    --task-classes 0,1 \
    --security-version 1 \
    --valid-days 365 \
    --out-dir     security/payload_trust/manifest

# 4. Üretim anchor'ını ekle (genel anahtar)
./tools/xrom_sign_payload.py anchor \
    --key    /secure/xrom-keys/xrom-payload-ed25519.pem \
    --key-id xrom-payload-root-01 \
    --min-security-version 1 \
    --out    security/payload_trust/trust_anchors.json

# 5. Cihaza gitmeden önce doğrula
./tools/xrom_verify_manifest.py \
    --manifest   security/payload_trust/manifest/xrom_payload_manifest.json \
    --signature  security/payload_trust/manifest/xrom_payload_manifest.json.sig \
    --anchors    security/payload_trust/trust_anchors.json \
    --apk        out/target/product/x1/system_ext/app/XVaultPayload/XVaultPayload.apk \
    --payload-lib out/.../libxvault_payload.so \
    --vm-config  device/x1/microdroid/xvault/assets/vm_config.json
```

İmzalama bittikten sonra iki `prebuilt_etc` modülünü `../Android.bp` içine ekleyin
ve `PRODUCT_PACKAGES`'a yazın:

```
prebuilt_etc {
    name: "xrom_payload_manifest",
    src: "manifest/xrom_payload_manifest.json",
    filename: "xrom_payload_manifest.json",
    sub_dir: "xrom/trust",
    system_ext_specific: true,
}

prebuilt_etc {
    name: "xrom_payload_manifest_sig",
    src: "manifest/xrom_payload_manifest.json.sig",
    filename: "xrom_payload_manifest.sig",
    sub_dir: "xrom/trust",
    system_ext_specific: true,
}
```

Modüller kaynak dosyalar var olmadan tanımlanamaz; bu yüzden imzalama adımından
sonra eklenirler. Kurulum yolu `VmSpec.h` içindeki `kPayloadTrustRoot` ile
`sepolicy/system_ext_private/file_contexts` içindeki etiketin aynı olmasını
gerektirir — `tools/xrom_preflight.py` üçünü de karşılaştırır.

## `payload_lib_sha256` neden derlenmiş `.so` üzerinden hesaplanır

Guest, `kGuestHello` içinde `/proc/self/exe`'yi ölçer. `use_embedded_native_libs:
true` ile APK içindeki kütüphane sıkıştırılmadan ve sayfa hizalı saklandığı için
çıkarılan baytlar derlenen baytlarla aynıdır; iki ölçüm bu yüzden karşılaştırılabilir.
APK'yı imzaladıktan sonra `.so`'yu yeniden derlerseniz manifest geçersiz olur —
olması gereken de budur.

## Özel anahtarlar

Bu ağacın hiçbir yerine özel anahtar konmaz. `xrom-payload-dev-*` anchor'ları
yalnızca geliştirme amaçlıdır ve **üretim imajına girmemelidir**; sürümde
`--key-id xrom-payload-root-01` gibi bir üretim anahtarı kullanılmalı ve geliştirme
anchor'ı `enabled: false` yapılmalıdır.
