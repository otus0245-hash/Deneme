# Deneme — Bot Paneli

Python botlarını web arayüzünden yöneten küçük Go paneli (`go run .` → http://127.0.0.1:8080).

## Giriş ve hesaplar

İlk çalıştırmada `admin` hesabı oluşturulur ve rastgele şifresi terminale **bir kez** yazılır.
Kendin belirlemek ya da unuttuğun admin şifresini sıfırlamak için:

```bash
PANEL_ADMIN_PASSWORD='en-az-8-karakter' go run .
```

Hesaplar `data/users.json` içinde (PBKDF2 ile hashlenmiş şifre) tutulur; dosya `.gitignore`'dadır, repoya gitmez.

### Yetkiler

| Yetki | Anlamı |
|---|---|
| `bots.view` | Botları ve konsol çıktısını görür |
| `bots.control` | Başlat / durdur / yeniden başlat / komut gönder |
| `bots.create` / `bots.edit` / `bots.delete` | Bot oluştur / düzenle / sil |
| `files.view` | Dosyaları listele, oku, indir |
| `files.write` | Dosya düzenle/oluştur, klasör aç, yeniden adlandır |
| `files.upload` | Dosya yükle |
| `files.delete` | Dosya/klasör sil |
| `db.view` / `db.write` | Veritabanı salt okunur / yazma |
| `users.create` / `users.delete` | Alt hesap oluştur / sil |
| `perms.grant` | Yetki ver, dosya engelini kaldır |
| `perms.revoke` | Yetki al, dosya erişimini engelle |

### Kurallar

- **Admin** her şeyi yapar, silinemez ve başka biri tarafından değiştirilemez.
- Herkes yalnızca **kendi oluşturduğu hesapları** (ve onların altındakileri) yönetir; kendini, üstünü ya da yan hesapları yönetemez.
- **Yetki verirken**: yetkiyi veren kişide *ve* hesabın üst hesabında da o yetki olmalı.
  Örneğin `perms.grant` var ama `perms.revoke` yoksa, kimseye `perms.revoke` veremez.
- Alt hesap üst hesabından fazla yetkiye sahip olamaz. Bir hesaptan yetki alınırsa altındakilerden de alınır.
- Yetki verme yetkisi olmayan biri, başlangıç yetkisi olan hesap oluşturamaz (yetkisiz oluşturur).
- Hesap silinince altındaki hesaplar da silinir ve oturumları kapanır.

### Dosya engelleri

Bir hesap için bir bot içindeki (ya da tüm botlardaki) belirli bir yol engellenebilir. Engelli yol listede görünmez;
okunamaz, indirilemez, değiştirilemez, silinemez, üzerine yüklenemez. Engeller alt hesaplara **miras kalır**.
Engel eklemek `perms.revoke`, kaldırmak `perms.grant` ister; kimse kendisine de uygulanan bir engeli başkası için kaldıramaz.

> ⚠ **Önemli:** Dosya engelleri panel arayüzünde uygulanır, işletim sistemi seviyesinde değil.
> `bots.control` + (`files.write` veya `files.upload`) yetkileri birleşince bir hesap sunucuda Python kodu
> çalıştırabilir; bu da engelleri, `data/users.json` dosyasını ve diğer botların dosyalarını okuyabilmek demektir.
> Bu yetkileri yalnızca güvendiğin hesaplara ver.

Yetki ile ilgili tüm işlemler terminale `[yetki] ...` satırıyla kaydedilir.
