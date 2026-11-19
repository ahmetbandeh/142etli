# 1.42 Etliekmek – Dijital Menü (Cloudflare Workers)

Menü sitesi + yönetici paneli. Cloudflare Workers, Static Assets ve KV üzerinde çalışır.

- Menü: `/`
- Yönetici paneli: `/admin` (fiyat, ürün adı, açıklama, etiket, kalori düzenleme / ürün ekleme-silme / şifre değiştirme)

## Yapı
- `public/index.html` – menü sayfası
- `public/admin.html` – yönetici paneli
- `public/menu.js` – varsayılan menü verisi (panel kaydedince KV'deki veri bunun üstüne yazılır)
- `public/img/` – fotoğraflar
- `src/worker.js` – Worker (giriş, oturum, KV kaydı)
- `wrangler.jsonc` – Cloudflare ayarı (KV bağlantısı dahil)

## Yayınlama (GitHub ile)
1. Dosyaları GitHub reposuna yükleyin.
2. Cloudflare → **Workers & Pages → Create → Import a repository** → repoyu seçin.
3. Build command: boş · Deploy command: `npx wrangler deploy` → Deploy.
   (KV alanı `MENU_KV` ilk deploy'da otomatik oluşturulur.)
4. **Worker → Settings → Variables and Secrets** bölümünden şu **Secret**'ları ekleyin:
   - `ADMIN_USERNAME` – yönetici kullanıcı adı
   - `ADMIN_PASSWORD` – yönetici şifresi (güçlü seçin)
   - `SESSION_SECRET` – uzun rastgele metin (isteğe bağlı ama önerilir)
   Ekledikten sonra **Deploy**'a basın / yeniden deploy edin.
5. `https://<worker-adresiniz>/admin` adresinden giriş yapın.

Not: Otomatik KV oluşmazsa Cloudflare → Storage & Databases → KV'den bir namespace oluşturup
`wrangler.jsonc` içindeki `kv_namespaces` satırını `{ "binding": "MENU_KV", "id": "<namespace-id>" }` yapın.

## Panelin çalışma şekli
- Giriş kontrolü sunucuda (Worker) yapılır; oturum HttpOnly çerezdir, hatalı girişlerde IP başına sınır vardır.
- "Kaydet ve yayınla" menüyü KV'ye yazar; site `menu.js` üzerinden bunu okur.
- Panelden şifre değiştirirseniz yeni bilgi KV'de (PBKDF2 ile hashlenmiş) saklanır ve secret'ların yerine geçer.
  Şifreyi unutursanız KV'deki `cred` anahtarını silin; secret'lardaki bilgiyle girebilirsiniz.
- Yeni eklenen ürünlerin fotoğrafı olmaz. Fotoğraf için dosyayı `public/img/thumb` ve `public/img/large`
  içine `<anahtar>.jpg` olarak koyup `menu.js` içindeki ürün satırının son alanına anahtarı yazın.

## Bilgisayardan
```
npm install
cp .dev.vars.example .dev.vars   # kendi bilgilerinizi yazın
npm run dev                      # yerel test
npm run deploy                   # yayınla
```
