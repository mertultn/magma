## Magma
Kişilerin kendi aralarında güvenli ve hızlı bir şekilde iletişim kurmasına olanak sağlayan tamamen açık kaynaklı bir uygulamadır.

**Not:** *Magma henüz geliştirme aşamasındadır.*

## ✦ Özellikler

### Mesajlaşma
- Gecikmesiz mesajlaşma
- Mesaj geçmişi
- Mesaj silme/düzenleme
  
### Kullanıcılar
- Kullanıcı profilleri
- Kullanıcı durumları
- Doğrudan mesajlaşma

### ⚡ Gerçek Zamanlı
Magma, iletişimi gerçek zamanlı olarak gerçekleştirir.
Mesajlar ve kullanıcı durumları bağlantı üzerinden
anlık olarak güncellenir.

## Kurulum

### Başlangıç (Geliştirme)

```bash
# Backend setup
cd server
npm install
cp .env.example .env
# DATABASE_URL'i .env'de ayarla
npm start

# Frontend setup (başka terminal)
cd client/matco
npm install
npm run tauri dev
```

### Production Deployment

1. **Ortam Değişkenleri**: `.env.example`'dan yapılandırın
2. **Node.js**: >=18 versiyonu gereklidir
3. **PostgreSQL**: Veritabanı bağlantı string'i sağlayın
4. **Security**: `NODE_ENV=production` ayarlayın

## 🔒 Güvenlik

- ✅ CORS + Security Headers (HSTS, X-Frame-Options, vb.)
- ✅ Input validation ve sanitization
- ✅ Bcrypt ile şifre hashleme
- ✅ PostgreSQL parametrized queries (SQL injection koruması)
- ✅ Error handling (production'da sensitive bilgiler leak etmez)
- ✅ WebSocket authentication
- ⏳ Rate limiting (geliştirilmesi devam ediyor)
- ⏳ Two-factor authentication (planlıyor)

## Download

[magmas.duckdns.org](https://magmas.duckdns.org) üzerinden Windows için indirebilirsiniz.
**NOT:** Magma henüz geliştirme aşamasındadır. Bu sebeple şu an yalnızca Windows için indirilebilir. İleride Android ve diğer platformlar için de hazır olacaktır.
