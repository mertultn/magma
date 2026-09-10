const http = require('http');
const os = require('os');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');

// ================= ORTAM DEĞİŞKENLERİ DOĞRULAMASI =================
const REQUIRED_ENV_VARS = ['DATABASE_URL'];
for (const envVar of REQUIRED_ENV_VARS) {
    if (!process.env[envVar]) {
        console.error(`[HATA] Gerekli ortam değişkeni bulunamadı: ${envVar}`);
        process.exit(1);
    }
}
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PRODUCTION = NODE_ENV === 'production';

// Beklenmeyen bir hata (yakalanmamış exception/promise reddi) tüm sunucuyu
// çökertip herkesi bağlantıdan düşürmesin diye son bir güvenlik ağı.
process.on('unhandledRejection', (err) => {
    console.error('[Yakalanmamış promise hatası]', err);
});
process.on('uncaughtException', (err) => {
    console.error('[Yakalanmamış hata]', err);
    process.exit(1);
});

// ================= INPUT DOĞRULAMA YARDIMCILARI =================
function validateUsername(username) {
    if (typeof username !== 'string') return null;
    const trimmed = username.trim().slice(0, 32);
    return /^[a-zA-Z0-9_]{1,32}$/.test(trimmed) ? trimmed : null;
}

function validatePassword(password) {
    return typeof password === 'string' && password.length >= 6 && password.length <= 128;
}

function validateEmail(email) {
    return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function sanitizeText(text, maxLength = 2000) {
    if (typeof text !== 'string') return '';
    return text.trim().slice(0, maxLength);
}

function sanitizeHtml(html) {
    if (typeof html !== 'string') return '';
    return html.replace(/[<>"'&]/g, char => ({
        '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '&': '&amp;'
    }[char]));
}

function sendError(ws, message, code = 400) {
    const errorMsg = IS_PRODUCTION ? 'Sunucu hatası oluştu.' : message;
    send(ws, { type: 'error', message: errorMsg, code });
}

// ================= RATE LIMITING (Brute Force Korusu) =================
const RATE_LIMIT_MAX_MESSAGES = 30;  // 30 saniyede max mesaj
const RATE_LIMIT_WINDOW_MS = 30000;  // 30 saniye penceresi
const RATE_LIMIT_AUTH_MAX = 5;       // 30 saniyede max 5 login denemesi

class RateLimiter {
    constructor(maxRequests, windowMs) {
        this.maxRequests = maxRequests;
        this.windowMs = windowMs;
        this.requests = new Map();
    }

    isLimited(id) {
        const now = Date.now();
        if (!this.requests.has(id)) {
            this.requests.set(id, [now]);
            return false;
        }
        let timestamps = this.requests.get(id);
        timestamps = timestamps.filter(t => now - t < this.windowMs);

        if (timestamps.length >= this.maxRequests) {
            this.requests.set(id, timestamps);
            return true;
        }

        timestamps.push(now);
        this.requests.set(id, timestamps);
        return false;
    }

    reset(id) {
        this.requests.delete(id);
    }
}

const rateLimitGeneral = new RateLimiter(RATE_LIMIT_MAX_MESSAGES, RATE_LIMIT_WINDOW_MS);
const rateLimitAuth = new RateLimiter(RATE_LIMIT_AUTH_MAX, RATE_LIMIT_WINDOW_MS);

// ================= CORS ORIGINS WHITELIST =================
const ALLOWED_ORIGINS = (
    process.env.CORS_ORIGINS ?
        process.env.CORS_ORIGINS.split(',').map(o => o.trim()) :
        ['http://localhost:3000', 'http://localhost:5173', 'http://localhost:7777']
);

function isOriginAllowed(origin) {
    if (IS_PRODUCTION && process.env.CORS_ORIGINS) {
        return ALLOWED_ORIGINS.includes(origin);
    }
    // Development'da tüm localhost'ları izin ver
    return !IS_PRODUCTION || origin?.includes('localhost') || origin?.includes('127.0.0.1');
}

// ================= MESSAGE TYPE WHITELIST =================
const ALLOWED_MESSAGE_TYPES = new Set([
    'register', 'login', 'logout',
    'get-notification-prefs', 'set-notification-prefs', 'set-guild-notification-pref', 'set-channel-notification-pref',
    'discover', 'search', 'join-guild-direct', 'join-guild',
    'create-guild', 'update-guild', 'delete-guild', 'leave-guild',
    'create-category', 'update-category', 'delete-category',
    'create-channel', 'delete-channel', 'update-channel',
    'select-channel', 'select-guild', 'chat', 'edit-message', 'delete-message', 'pin-message', 'unpin-message',
    'update-profile', 'friend-request', 'accept-friend-request', 'deny-friend-request', 'remove-friend',
    'block-user', 'unblock-user', 'block-list',
    'dm-send', 'dm-message', 'dm-edit', 'dm-delete', 'dm-pin', 'dm-unpin',
    'dm-conversations', 'dm-history', 'dm-set-read', 'dm-hide', 'dm-unhide', 'dm-settings',
    'select-voice-channel', 'leave-voice-channel', 'mute', 'unmute',
    'ban-member', 'unban-member', 'kick-member', 'promote-member', 'demote-member',
    'history', 'pinned-messages',
]);

function isValidUserId(id) {
    return typeof id === 'number' && id > 0 && Number.isInteger(id);
}

function isValidGuildId(id) {
    return typeof id === 'number' && id > 0 && Number.isInteger(id);
}

function isValidChannelId(id) {
    return typeof id === 'number' && id > 0 && Number.isInteger(id);
}

// Permission checker: admin ya da owner mutü
function isOwnerOrAdmin(membership) {
    return membership && (membership.role === 'owner' || membership.role === 'admin');
}

// Permission checker: sadece owner
function isOwner(membership) {
    return membership && membership.role === 'owner';
}
// DATABASE_URL ortam değişkeninden okunuyor (Render Postgres "Internal
// Database URL" veya başka bir Postgres sağlayıcısının connection string'i).
if (!process.env.DATABASE_URL) {
    console.warn('[DB] UYARI: DATABASE_URL ortam değişkeni bulunamadı!');
    console.warn('[DB] Yerelde çalıştırıyorsan .env dosyana ya da ortam');
    console.warn('[DB] değişkenlerine bir Postgres connection string eklemelisin.');
} else {
    console.log('[DB] PostgreSQL veritabanına bağlanılıyor...');
}

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    // Render'ın internal Postgres URL'i SSL gerektirmez ama external
    // bağlantılarda (ör. Render dışından, ya da bazı sağlayıcılarda)
    // SSL zorunlu olabilir. rejectUnauthorized:false, self-signed
    // sertifikalarla da (Render'ın kendi sertifikaları gibi) çalışmasını sağlar.
    ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes('localhost')
        ? { rejectUnauthorized: false }
        : false,
});

pool.on('error', (err) => {
    // Havuzdaki boşta bekleyen bir bağlantı koparsa süreç çökmesin.
    console.error('[DB] Beklenmeyen havuz hatası:', err);
});

// better-sqlite3'teki prepare(sql).get/.all/.run alışkanlığını korumak için
// ince bir sarmalayıcı: aynı isimlerle çalışıyor ama artık asenkron (Promise).
// SQLite tarzı "?" placeholder'ları otomatik olarak Postgres'in "$1,$2,.."
// biçimine çevriliyor, böylece aşağıdaki sorgu tanımları değişmeden kalabiliyor.
function toPgPlaceholders(sql) {
    let i = 0;
    return sql.replace(/\?/g, () => `$${++i}`);
}

function prepare(sql) {
    const pgSql = toPgPlaceholders(sql);
    return {
        async get(...args) {
            const res = await pool.query(pgSql, args);
            return res.rows[0];
        },
        async all(...args) {
            const res = await pool.query(pgSql, args);
            return res.rows;
        },
        async run(...args) {
            const res = await pool.query(pgSql, args);
            return {
                // lastInsertRowid çalışması için INSERT sorgularına "RETURNING id" eklendi.
                lastInsertRowid: res.rows[0] && res.rows[0].id !== undefined
                    ? Number(res.rows[0].id) : undefined,
                changes: res.rowCount,
            };
        },
    };
}

// db.exec(...) yerine kullanılan asenkron karşılığı (şema/migrasyon için).
async function exec(sql) {
    await pool.query(sql);
}

const PORT = process.env.PORT ? Number(process.env.PORT) : 7777;
const PUBLIC_DIR = path.join(__dirname, 'public');

// Mesaj eklerinde (resim/video/ses/dosya) base64 data URL'in izin verilen
// azami uzunluğu. İstemci tarafında ham dosya ~8MB ile sınırlanıyor;
// base64 kodlaması boyutu ~%37 artırdığı için biraz payla sınır koyuyoruz.
const MAX_ATTACHMENT_DATAURL_LENGTH = 12 * 1024 * 1024;

const MIME_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.ico': 'image/x-icon',
};

// ================= VERİTABANI ŞEMASI =================
async function initSchema() {
    await exec(`CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT
    )`);

    await exec(`CREATE TABLE IF NOT EXISTS guilds (
        id SERIAL PRIMARY KEY,
        name TEXT,
        owner_id INTEGER,
        invite_code TEXT UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    await exec(`CREATE TABLE IF NOT EXISTS guild_members (
        guild_id INTEGER,
        user_id INTEGER,
        role TEXT DEFAULT 'member',
        PRIMARY KEY (guild_id, user_id)
    )`);

    await exec(`CREATE TABLE IF NOT EXISTS guild_bans (
        guild_id INTEGER,
        user_id INTEGER,
        username TEXT,
        banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (guild_id, user_id)
    )`);

    await exec(`CREATE TABLE IF NOT EXISTS categories (
        id SERIAL PRIMARY KEY,
        guild_id INTEGER,
        name TEXT,
        position INTEGER DEFAULT 0
    )`);

    await exec(`CREATE TABLE IF NOT EXISTS channels (
        id SERIAL PRIMARY KEY,
        guild_id INTEGER,
        name TEXT,
        type TEXT DEFAULT 'text',
        position INTEGER DEFAULT 0,
        category_id INTEGER
    )`);

    await exec(`CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        channel_id INTEGER,
        sender TEXT,
        user_id INTEGER,
        content TEXT,
        edited_at TIMESTAMP,
        pinned_at TIMESTAMP,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    // Postgres, ADD COLUMN IF NOT EXISTS'i doğrudan destekliyor, bu yüzden
    // SQLite'daki try/catch ile "zaten var" hatasını yutma numarasına gerek yok.
    await exec('ALTER TABLE messages ADD COLUMN IF NOT EXISTS pinned_at TIMESTAMP');

    // Eski (kanal öncesi) veritabanından geliyorsan messages tablosunda
    // channel_id sütunu eksik olabilir.
    await exec('ALTER TABLE messages ADD COLUMN IF NOT EXISTS channel_id INTEGER');
    await exec('ALTER TABLE messages ADD COLUMN IF NOT EXISTS user_id INTEGER');
    await exec('ALTER TABLE messages ADD COLUMN IF NOT EXISTS edited_at TIMESTAMP');

    // Ek dosya (resim/video/ses/genel dosya) desteği: base64 data URL olarak
    // saklanır (mevcut avatar/banner ile aynı basit yaklaşım).
    await exec('ALTER TABLE messages ADD COLUMN IF NOT EXISTS attachment_data TEXT');
    await exec('ALTER TABLE messages ADD COLUMN IF NOT EXISTS attachment_type TEXT');
    await exec('ALTER TABLE messages ADD COLUMN IF NOT EXISTS attachment_name TEXT');

    await exec('ALTER TABLE channels ADD COLUMN IF NOT EXISTS category_id INTEGER');

    // Eski veritabanlarında users tablosunda avatar/banner sütunu olmayabilir.
    await exec('ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar TEXT');
    await exec('ALTER TABLE users ADD COLUMN IF NOT EXISTS banner TEXT');
    await exec('ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP');
    await exec("UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL");

    // Eski veritabanlarında guilds tablosunda avatar/description/banner/is_private sütunu olmayabilir.
    await exec('ALTER TABLE guilds ADD COLUMN IF NOT EXISTS avatar TEXT');
    await exec('ALTER TABLE guilds ADD COLUMN IF NOT EXISTS description TEXT');
    await exec('ALTER TABLE guilds ADD COLUMN IF NOT EXISTS banner TEXT');
    await exec('ALTER TABLE guilds ADD COLUMN IF NOT EXISTS is_private INTEGER DEFAULT 0');

    // Süreli yasaklama (geçici kick) desteği: NULL = süresiz/kalıcı yasak.
    await exec('ALTER TABLE guild_bans ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP');

    // ================= BİLDİRİM TERCİHLERİ =================
    // Kullanıcı bazlı genel ayarlar: bildirimler tamamen açık mı, sadece
    // etiketlenmelerde mi gelsin, ortak sunucudaki biri aktif olunca bildir mi.
    await exec(`CREATE TABLE IF NOT EXISTS user_notification_prefs (
        user_id INTEGER PRIMARY KEY,
        global_enabled INTEGER DEFAULT 1,
        mentions_only INTEGER DEFAULT 0,
        shared_guild_online_enabled INTEGER DEFAULT 0
    )`);

    // Sunucu bazlı override: kullanıcı belirli bir sunucu için genel ayarı ezebilir.
    // mode: 'default' | 'all' | 'mentions_only' | 'none'
    await exec(`CREATE TABLE IF NOT EXISTS guild_notification_prefs (
        guild_id INTEGER,
        user_id INTEGER,
        mode TEXT DEFAULT 'default',
        PRIMARY KEY (guild_id, user_id)
    )`);

    // Kanal bazlı override: sunucu ayarını da ezer, en spesifik seviye budur.
    await exec(`CREATE TABLE IF NOT EXISTS channel_notification_prefs (
        channel_id INTEGER,
        user_id INTEGER,
        mode TEXT DEFAULT 'default',
        PRIMARY KEY (channel_id, user_id)
    )`);

    // ================= ARKADAŞLIK =================
    // Tek satır iki yönü de temsil eder: pending -> istek bekliyor,
    // accepted -> arkadaşlar. requester_id isteği atan, addressee_id alan taraf.
    await exec(`CREATE TABLE IF NOT EXISTS friend_requests (
        id SERIAL PRIMARY KEY,
        requester_id INTEGER,
        addressee_id INTEGER,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (requester_id, addressee_id)
    )`);

    // ================= ENGELLEME =================
    await exec(`CREATE TABLE IF NOT EXISTS blocked_users (
        user_id INTEGER,
        blocked_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id, blocked_id)
    )`);

    // Not: guild_members.role sütunu zaten TEXT, 'admin' değeri için ek migrasyon gerekmiyor.

    // ================= ÖZEL MESAJLAR (DM) =================
    // İki kullanıcı arasında tek bir konuşma satırı garanti etmek için
    // user_a her zaman user_b'den küçük tutulur (kanonik sıra, bkz. canonicalPair).
    await exec(`CREATE TABLE IF NOT EXISTS dm_conversations (
        id SERIAL PRIMARY KEY,
        user_a INTEGER NOT NULL,
        user_b INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (user_a, user_b)
    )`);

    await exec(`CREATE TABLE IF NOT EXISTS dm_messages (
        id SERIAL PRIMARY KEY,
        conversation_id INTEGER,
        sender_id INTEGER,
        content TEXT,
        edited_at TIMESTAMP,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    await exec('ALTER TABLE dm_messages ADD COLUMN IF NOT EXISTS attachment_data TEXT');
    await exec('ALTER TABLE dm_messages ADD COLUMN IF NOT EXISTS attachment_type TEXT');
    await exec('ALTER TABLE dm_messages ADD COLUMN IF NOT EXISTS attachment_name TEXT');
    // Sunuculardaki kanal mesajlarıyla aynı mantık: DM'de de mesaj sabitleme.
    await exec('ALTER TABLE dm_messages ADD COLUMN IF NOT EXISTS pinned_at TIMESTAMP');


    // Her kullanıcının her konuşmayı en son ne zaman okuduğu (okunmamış sayısı için).
    await exec(`CREATE TABLE IF NOT EXISTS dm_reads (
        conversation_id INTEGER,
        user_id INTEGER,
        last_read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (conversation_id, user_id)
    )`);

    // Kullanıcı bazlı DM gizlilik ayarları.
    // allow_from: 'everyone' | 'friends' | 'nobody' — temel kural.
    // allow_known: true ise, allow_from ne olursa olsun, daha önce kendisiyle
    // gerçek bir konuşma geçmişi olan kişiler (ör. arkadaşlıktan çıkarılmış
    // olsa bile) yine de mesaj atabilir. Engelleme her zaman her şeyi ezer.
    await exec(`CREATE TABLE IF NOT EXISTS dm_settings (
        user_id INTEGER PRIMARY KEY,
        allow_from TEXT DEFAULT 'everyone',
        allow_known INTEGER DEFAULT 1
    )`);

    // Kullanıcının anasayfadaki "son sohbetler" listesinden gizlediği
    // konuşmalar (konuşma silinmez, sadece o kullanıcı için listeden çıkar).
    await exec(`CREATE TABLE IF NOT EXISTS dm_hidden (
        user_id INTEGER,
        conversation_id INTEGER,
        PRIMARY KEY (user_id, conversation_id)
    )`);
}

const registerUserStmt = prepare('INSERT INTO users (username, password) VALUES (?, ?) RETURNING id');
const findUserByName = prepare('SELECT * FROM users WHERE username = ?');
const findUserById = prepare('SELECT * FROM users WHERE id = ?');
const updateUsernameStmt = prepare('UPDATE users SET username = ? WHERE id = ?');
const updatePasswordStmt = prepare('UPDATE users SET password = ? WHERE id = ?');
const updateAvatarStmt = prepare('UPDATE users SET avatar = ? WHERE id = ?');
const updateBannerStmt = prepare('UPDATE users SET banner = ? WHERE id = ?');

const insertGuild = prepare('INSERT INTO guilds (name, owner_id, invite_code) VALUES (?, ?, ?) RETURNING id');
const findGuildByInvite = prepare('SELECT * FROM guilds WHERE invite_code = ?');
const findGuildById = prepare('SELECT * FROM guilds WHERE id = ?');
const updateGuildStmt = prepare('UPDATE guilds SET name = ?, avatar = ?, description = ?, banner = ?, is_private = ? WHERE id = ?');
const deleteGuildStmt = prepare('DELETE FROM guilds WHERE id = ?');
const deleteGuildMembersStmt = prepare('DELETE FROM guild_members WHERE guild_id = ?');
const deleteGuildChannelsStmt = prepare('DELETE FROM channels WHERE guild_id = ?');
const deleteGuildMessagesStmt = prepare('DELETE FROM messages WHERE channel_id IN (SELECT id FROM channels WHERE guild_id = ?)');
const deleteGuildBansStmt = prepare('DELETE FROM guild_bans WHERE guild_id = ?');
const removeMemberStmt = prepare('DELETE FROM guild_members WHERE guild_id = ? AND user_id = ?');

const addMember = prepare('INSERT INTO guild_members (guild_id, user_id, role) VALUES (?, ?, ?) ON CONFLICT (guild_id, user_id) DO NOTHING');
const findMembership = prepare('SELECT * FROM guild_members WHERE guild_id = ? AND user_id = ?');
const insertBan = prepare(`INSERT INTO guild_bans (guild_id, user_id, username, expires_at) VALUES (?, ?, ?, ?)
    ON CONFLICT (guild_id, user_id) DO UPDATE SET username = EXCLUDED.username, banned_at = CURRENT_TIMESTAMP, expires_at = EXCLUDED.expires_at`);
// Süresi dolmuş geçici yasaklar artık aktif sayılmaz (expires_at NULL ise kalıcı yasaktır).
const findBan = prepare("SELECT * FROM guild_bans WHERE guild_id = ? AND user_id = ? AND (expires_at IS NULL OR expires_at > NOW())");
const removeBan = prepare('DELETE FROM guild_bans WHERE guild_id = ? AND user_id = ?');
const guildBansStmt = prepare("SELECT * FROM guild_bans WHERE guild_id = ? AND (expires_at IS NULL OR expires_at > NOW()) ORDER BY banned_at DESC");
const discoverGuildsStmt = prepare(`
    SELECT g.id, g.name, g.avatar, g.banner, g.description,
           (SELECT COUNT(*) FROM guild_members gm WHERE gm.guild_id = g.id) AS member_count,
           (SELECT COUNT(*) FROM messages m JOIN channels c ON c.id = m.channel_id
            WHERE c.guild_id = g.id AND m.timestamp >= NOW() - INTERVAL '7 days') AS recent_messages
    FROM guilds g
    WHERE COALESCE(g.is_private, 0) = 0
    ORDER BY recent_messages DESC, member_count DESC, g.id DESC
    LIMIT 16
`);
const searchGuildsStmt = prepare(`
    SELECT g.id, g.name, g.avatar, g.banner, g.description,
           (SELECT COUNT(*) FROM guild_members gm WHERE gm.guild_id = g.id) AS member_count
    FROM guilds g
    WHERE (g.name ILIKE ? OR g.description ILIKE ?) AND COALESCE(g.is_private, 0) = 0
    ORDER BY member_count DESC
    LIMIT 25
`);
const searchUsersStmt = prepare('SELECT id, username, avatar FROM users WHERE username ILIKE ? ORDER BY username LIMIT 25');
const userGuilds = prepare(`
    SELECT g.id, g.name, g.owner_id, g.invite_code, g.avatar, g.banner, g.description, g.is_private, gm.role
    FROM guilds g JOIN guild_members gm ON gm.guild_id = g.id
    WHERE gm.user_id = ?
    ORDER BY g.id
`);
const guildMembersStmt = prepare(`
    SELECT u.id, u.username, u.avatar, u.banner, gm.role
    FROM guild_members gm JOIN users u ON u.id = gm.user_id
    WHERE gm.guild_id = ?
`);

// ================= BİLDİRİM TERCİHLERİ SORGULARI =================
const getUserNotifPrefsStmt = prepare('SELECT * FROM user_notification_prefs WHERE user_id = ?');
const upsertUserNotifPrefsStmt = prepare(`
    INSERT INTO user_notification_prefs (user_id, global_enabled, mentions_only, shared_guild_online_enabled)
    VALUES (?, ?, ?, ?)
    ON CONFLICT (user_id) DO UPDATE SET
        global_enabled = EXCLUDED.global_enabled,
        mentions_only = EXCLUDED.mentions_only,
        shared_guild_online_enabled = EXCLUDED.shared_guild_online_enabled
`);

const getGuildNotifOverridesStmt = prepare('SELECT guild_id, mode FROM guild_notification_prefs WHERE user_id = ?');
const getGuildNotifPrefStmt = prepare('SELECT mode FROM guild_notification_prefs WHERE guild_id = ? AND user_id = ?');
const upsertGuildNotifPrefStmt = prepare(`
    INSERT INTO guild_notification_prefs (guild_id, user_id, mode) VALUES (?, ?, ?)
    ON CONFLICT (guild_id, user_id) DO UPDATE SET mode = EXCLUDED.mode
`);

const getChannelNotifOverridesStmt = prepare('SELECT channel_id, mode FROM channel_notification_prefs WHERE user_id = ?');
const getChannelNotifPrefStmt = prepare('SELECT mode FROM channel_notification_prefs WHERE channel_id = ? AND user_id = ?');
const upsertChannelNotifPrefStmt = prepare(`
    INSERT INTO channel_notification_prefs (channel_id, user_id, mode) VALUES (?, ?, ?)
    ON CONFLICT (channel_id, user_id) DO UPDATE SET mode = EXCLUDED.mode
`);

// Bir kullanıcının ortak olduğu tüm sunucuların üye listelerini (kendisi hariç)
// tek seferde getirir — "ortak sunucudaki biri aktif oldu" bildirimi için kullanılır.
const usersSharingGuildsWithStmt = prepare(`
    SELECT DISTINCT gm2.user_id AS id
    FROM guild_members gm1
    JOIN guild_members gm2 ON gm2.guild_id = gm1.guild_id AND gm2.user_id != gm1.user_id
    WHERE gm1.user_id = ?
`);

// ================= ARKADAŞLIK SORGULARI =================
const insertFriendRequestStmt = prepare(`
    INSERT INTO friend_requests (requester_id, addressee_id) VALUES (?, ?)
    ON CONFLICT (requester_id, addressee_id) DO NOTHING RETURNING id
`);
const findFriendRequestBetweenStmt = prepare(`
    SELECT * FROM friend_requests WHERE (requester_id = ? AND addressee_id = ?) OR (requester_id = ? AND addressee_id = ?)
`);
const findFriendRequestByIdStmt = prepare('SELECT * FROM friend_requests WHERE id = ?');
const acceptFriendRequestStmt = prepare("UPDATE friend_requests SET status = 'accepted' WHERE id = ?");
const deleteFriendRequestByIdStmt = prepare('DELETE FROM friend_requests WHERE id = ?');
const deleteFriendshipBetweenStmt = prepare(`
    DELETE FROM friend_requests WHERE (requester_id = ? AND addressee_id = ?) OR (requester_id = ? AND addressee_id = ?)
`);
const friendsListStmt = prepare(`
    SELECT u.id, u.username, u.avatar, u.banner
    FROM friend_requests fr
    JOIN users u ON u.id = (CASE WHEN fr.requester_id = ? THEN fr.addressee_id ELSE fr.requester_id END)
    WHERE (fr.requester_id = ? OR fr.addressee_id = ?) AND fr.status = 'accepted'
    ORDER BY u.username
`);
const incomingFriendRequestsStmt = prepare(`
    SELECT fr.id, u.id AS user_id, u.username, u.avatar
    FROM friend_requests fr JOIN users u ON u.id = fr.requester_id
    WHERE fr.addressee_id = ? AND fr.status = 'pending'
    ORDER BY fr.created_at DESC
`);
const outgoingFriendRequestsStmt = prepare(`
    SELECT fr.id, u.id AS user_id, u.username, u.avatar
    FROM friend_requests fr JOIN users u ON u.id = fr.addressee_id
    WHERE fr.requester_id = ? AND fr.status = 'pending'
    ORDER BY fr.created_at DESC
`);
const deleteFriendRequestsInvolvingStmt = prepare('DELETE FROM friend_requests WHERE requester_id = ? OR addressee_id = ?');

// ================= ENGELLEME SORGULARI =================
const blockUserStmt = prepare('INSERT INTO blocked_users (user_id, blocked_id) VALUES (?, ?) ON CONFLICT DO NOTHING');
const unblockUserStmt = prepare('DELETE FROM blocked_users WHERE user_id = ? AND blocked_id = ?');
const isBlockedEitherWayStmt = prepare(`
    SELECT 1 FROM blocked_users WHERE (user_id = ? AND blocked_id = ?) OR (user_id = ? AND blocked_id = ?)
`);
const blockedListStmt = prepare(`
    SELECT u.id, u.username, u.avatar FROM blocked_users b JOIN users u ON u.id = b.blocked_id
    WHERE b.user_id = ? ORDER BY u.username
`);
const deleteBlocksInvolvingStmt = prepare('DELETE FROM blocked_users WHERE user_id = ? OR blocked_id = ?');

// ================= DM SORGULARI =================
const findDMConversationStmt = prepare('SELECT * FROM dm_conversations WHERE user_a = ? AND user_b = ?');
const insertDMConversationStmt = prepare('INSERT INTO dm_conversations (user_a, user_b) VALUES (?, ?) ON CONFLICT (user_a, user_b) DO NOTHING RETURNING id');

const insertDMMessageStmt = prepare('INSERT INTO dm_messages (conversation_id, sender_id, content, attachment_data, attachment_type, attachment_name) VALUES (?, ?, ?, ?, ?, ?) RETURNING id');
const dmHistoryStmt = prepare('SELECT * FROM dm_messages WHERE conversation_id = ? ORDER BY id DESC LIMIT 50');
const dmMessageCountStmt = prepare('SELECT COUNT(*)::int AS count FROM dm_messages WHERE conversation_id = ?');
const findDMMessageById = prepare('SELECT * FROM dm_messages WHERE id = ?');
const updateDMMessageStmt = prepare('UPDATE dm_messages SET content = ?, edited_at = CURRENT_TIMESTAMP WHERE id = ?');
const deleteDMMessageStmt = prepare('DELETE FROM dm_messages WHERE id = ?');
const pinDMMessageStmt = prepare('UPDATE dm_messages SET pinned_at = CURRENT_TIMESTAMP WHERE id = ?');
const unpinDMMessageStmt = prepare('UPDATE dm_messages SET pinned_at = NULL WHERE id = ?');
const pinnedDMMessagesStmt = prepare('SELECT * FROM dm_messages WHERE conversation_id = ? AND pinned_at IS NOT NULL ORDER BY pinned_at DESC');
const findDMConversationById = prepare('SELECT * FROM dm_conversations WHERE id = ?');

const upsertDMReadStmt = prepare(`
    INSERT INTO dm_reads (conversation_id, user_id, last_read_at) VALUES (?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT (conversation_id, user_id) DO UPDATE SET last_read_at = CURRENT_TIMESTAMP
`);

const getDMSettingsStmt = prepare('SELECT * FROM dm_settings WHERE user_id = ?');
const upsertDMSettingsStmt = prepare(`
    INSERT INTO dm_settings (user_id, allow_from, allow_known) VALUES (?, ?, ?)
    ON CONFLICT (user_id) DO UPDATE SET allow_from = EXCLUDED.allow_from, allow_known = EXCLUDED.allow_known
`);

// Bir kullanıcının tüm DM konuşmalarını, karşı taraf id'siyle, son mesajla
// ve okunmamış sayısıyla birlikte getirir. userId parametresi 5 kez geçer
// (CASE, iki alt sorgu, ve WHERE bacakları için).
const userDMConversationsStmt = prepare(`
    SELECT c.id AS conversation_id,
           CASE WHEN c.user_a = ? THEN c.user_b ELSE c.user_a END AS peer_id,
           (SELECT content FROM dm_messages m WHERE m.conversation_id = c.id ORDER BY m.id DESC LIMIT 1) AS last_content,
           (SELECT m.timestamp FROM dm_messages m WHERE m.conversation_id = c.id ORDER BY m.id DESC LIMIT 1) AS last_ts,
           (SELECT COUNT(*)::int FROM dm_messages m WHERE m.conversation_id = c.id
             AND m.sender_id != ?
             AND m.timestamp > COALESCE((SELECT last_read_at FROM dm_reads r WHERE r.conversation_id = c.id AND r.user_id = ?), to_timestamp(0))
           ) AS unread_count
    FROM dm_conversations c
    WHERE (c.user_a = ? OR c.user_b = ?)
      AND NOT EXISTS (SELECT 1 FROM dm_hidden h WHERE h.user_id = ? AND h.conversation_id = c.id)
`);
const hideDMConversationStmt = prepare(`
    INSERT INTO dm_hidden (user_id, conversation_id) VALUES (?, ?)
    ON CONFLICT (user_id, conversation_id) DO NOTHING
`);
const unhideDMConversationStmt = prepare('DELETE FROM dm_hidden WHERE user_id = ? AND conversation_id = ?');

// ================= HESAP SİLME SORGULARI =================
const ownedGuildsStmt = prepare('SELECT * FROM guilds WHERE owner_id = ?');
const otherGuildMembersOrderedStmt = prepare(`
    SELECT * FROM guild_members WHERE guild_id = ? AND user_id != ?
    ORDER BY (role = 'admin') DESC, user_id ASC
`);
const transferGuildOwnerStmt = prepare('UPDATE guilds SET owner_id = ? WHERE id = ?');
const setMemberRoleForTransferStmt = prepare("UPDATE guild_members SET role = 'owner' WHERE guild_id = ? AND user_id = ?");
const deleteAllMembershipsForUserStmt = prepare('DELETE FROM guild_members WHERE user_id = ?');
const anonymizeUserMessagesStmt = prepare("UPDATE messages SET sender = 'Silinmiş Kullanıcı', user_id = NULL WHERE user_id = ?");
const deleteUserNotifPrefsStmt = prepare('DELETE FROM user_notification_prefs WHERE user_id = ?');
const deleteGuildNotifPrefsForUserStmt = prepare('DELETE FROM guild_notification_prefs WHERE user_id = ?');
const deleteChannelNotifPrefsForUserStmt = prepare('DELETE FROM channel_notification_prefs WHERE user_id = ?');
const deleteUserByIdStmt = prepare('DELETE FROM users WHERE id = ?');

const deleteDMMessagesForUserStmt = prepare('DELETE FROM dm_messages WHERE conversation_id IN (SELECT id FROM dm_conversations WHERE user_a = ? OR user_b = ?)');
const deleteDMReadsForUserStmt = prepare('DELETE FROM dm_reads WHERE conversation_id IN (SELECT id FROM dm_conversations WHERE user_a = ? OR user_b = ?)');
const deleteDMConversationsForUserStmt = prepare('DELETE FROM dm_conversations WHERE user_a = ? OR user_b = ?');
const deleteDMSettingsForUserStmt = prepare('DELETE FROM dm_settings WHERE user_id = ?');

const insertCategory = prepare('INSERT INTO categories (guild_id, name, position) VALUES (?, ?, ?)');
const guildCategoriesStmt = prepare('SELECT * FROM categories WHERE guild_id = ? ORDER BY position, id');
const findCategoryById = prepare('SELECT * FROM categories WHERE id = ?');
const deleteCategoryStmt = prepare('DELETE FROM categories WHERE id = ?');
const uncategorizeChannelsStmt = prepare('UPDATE channels SET category_id = NULL WHERE category_id = ?');

const insertChannel = prepare('INSERT INTO channels (guild_id, name, type, position, category_id) VALUES (?, ?, ?, ?, ?)');
const guildChannelsStmt = prepare(`SELECT * FROM channels WHERE guild_id = ? ORDER BY type DESC, position, id`);
const findChannelById = prepare('SELECT * FROM channels WHERE id = ?');
const deleteChannelStmt = prepare('DELETE FROM channels WHERE id = ?');
const deleteChannelMessages = prepare('DELETE FROM messages WHERE channel_id = ?');

const insertMessage = prepare('INSERT INTO messages (channel_id, sender, user_id, content, attachment_data, attachment_type, attachment_name) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id');
const channelHistoryStmt = prepare(`
    SELECT m.id, m.sender, m.user_id, m.content, m.timestamp, m.edited_at, m.pinned_at, m.attachment_data, m.attachment_type, m.attachment_name, u.avatar
    FROM messages m LEFT JOIN users u ON u.username = m.sender
    WHERE m.channel_id = ? ORDER BY m.id DESC LIMIT 50
`);
const pinnedMessagesStmt = prepare(`
    SELECT m.id, m.sender, m.user_id, m.content, m.timestamp, m.edited_at, m.pinned_at, u.avatar
    FROM messages m LEFT JOIN users u ON u.username = m.sender
    WHERE m.channel_id = ? AND m.pinned_at IS NOT NULL ORDER BY m.pinned_at DESC
`);
const findMessageById = prepare('SELECT * FROM messages WHERE id = ?');
const updateMessageStmt = prepare('UPDATE messages SET content = ?, edited_at = CURRENT_TIMESTAMP WHERE id = ?');
const deleteMessageStmt = prepare('DELETE FROM messages WHERE id = ?');
const pinMessageStmt = prepare('UPDATE messages SET pinned_at = CURRENT_TIMESTAMP WHERE id = ?');
const unpinMessageStmt = prepare('UPDATE messages SET pinned_at = NULL WHERE id = ?');
const setMemberRoleStmt = prepare('UPDATE guild_members SET role = ? WHERE guild_id = ? AND user_id = ?');

function genInviteCode() {
    return crypto.randomBytes(4).toString('hex'); // örn: "a1b2c3d4"
}

async function createGuildWithDefaults(name, ownerId) {
    const invite = genInviteCode();
    const info = await insertGuild.run(name, ownerId, invite);
    const guildId = info.lastInsertRowid;
    await addMember.run(guildId, ownerId, 'owner');
    await insertChannel.run(guildId, 'genel', 'text', 0, null);
    await insertChannel.run(guildId, 'Genel Sesli', 'voice', 0, null);
    return await findGuildById.get(guildId);
}

// Sunucu sahibi VE yöneticiler kanal/kategori oluşturabilir & silebilir.
function canManageChannels(membership) {
    return !!membership && (membership.role === 'owner' || membership.role === 'admin');
}

// ================= DM YARDIMCI FONKSİYONLARI =================

// İki kullanıcı arasında her zaman aynı sırayla (küçük id önce) tutulan
// kanonik çift — böylece dm_conversations'ta tek satır garanti edilir.
function canonicalPair(a, b) {
    return a < b ? [a, b] : [b, a];
}

async function getOrCreateDMConversation(userIdA, userIdB) {
    const [a, b] = canonicalPair(userIdA, userIdB);
    let convo = await findDMConversationStmt.get(a, b);
    if (!convo) {
        await insertDMConversationStmt.run(a, b);
        convo = await findDMConversationStmt.get(a, b);
    }
    return convo;
}

// İki kullanıcı arasında gerçekten mesajlaşılmış (en az bir mesaj var) bir
// konuşma olup olmadığını söyler. "Eskiden konuştuysam" ayarı için kullanılır.
async function hasExistingDMConversation(userIdA, userIdB) {
    const [a, b] = canonicalPair(userIdA, userIdB);
    const convo = await findDMConversationStmt.get(a, b);
    if (!convo) return false;
    const countRow = await dmMessageCountStmt.get(convo.id);
    return !!countRow && countRow.count > 0;
}

// fromId kişisinin toId'ye DM atıp atamayacağına karar verir.
// Dönen değer: { allowed: boolean, reason?: 'self' | 'blocked' | 'restricted' }
async function canSendDM(fromId, toId) {
    if (fromId === toId) return { allowed: false, reason: 'self' };

    const blocked = await isBlockedEitherWayStmt.get(fromId, toId, toId, fromId);
    if (blocked) return { allowed: false, reason: 'blocked' };

    const settingsRow = await getDMSettingsStmt.get(toId);
    const allowFrom = settingsRow ? settingsRow.allow_from : 'everyone';
    const allowKnown = settingsRow ? !!settingsRow.allow_known : true;

    if (allowFrom === 'everyone') return { allowed: true };

    const friendship = await findFriendRequestBetweenStmt.get(fromId, toId, toId, fromId);
    if (friendship && friendship.status === 'accepted') return { allowed: true };

    // allow_from artık 'friends' ya da 'nobody': arkadaş değiller ama
    // "eskiden konuştuysa yine yazabilsin" ayarı açıksa geçmişe bakılır.
    if (allowKnown) {
        const known = await hasExistingDMConversation(fromId, toId);
        if (known) return { allowed: true };
    }

    return { allowed: false, reason: 'restricted' };
}

// ================= HTTP (STATİK DOSYA SUNUMU) =================
// CORS Headers
res.setHeader('Access-Control-Allow-Origin', '*');
res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
res.setHeader('Access-Control-Max-Age', '86400');

// Security Headers
res.setHeader('X-Content-Type-Options', 'nosniff');
res.setHeader('X-Frame-Options', 'DENY');
res.setHeader('X-XSS-Protection', '1; mode=block');
res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
if (IS_PRODUCTION) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' ws: wss:");
}

// OPTIONS isteğine cevap ver
if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
}

let reqPath = decodeURIComponent(req.url.split('?')[0]);
if (reqPath === '/') reqPath = '/index.html';
const filePath = path.join(PUBLIC_DIR, reqPath);

if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('Forbidden');
    return;
}

fs.readFile(filePath, (err, data) => {
    if (err) {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('Magma server is running.\n');
        return;
    }
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME_TYPES[ext] || 'application/octet-stream' });
    res.end(data);
});

const wss = new WebSocketServer({ server: httpServer });

/**
 * Her bağlantı için tutulan durum.
 * @type {Map<number, {ws: import('ws').WebSocket, userId:number|null, username:string|null,
 *                      guildId:number|null, channelId:number|null, voiceChannelId:number|null, muted:boolean}>}
 */
const clients = new Map();
let nextId = 1;

function send(ws, obj) {
    if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(obj));
}

// Bir kullanıcının (varsa birden fazla cihazdaki) tüm açık bağlantılarına mesaj yollar.
function sendToUser(userId, obj) {
    const data = JSON.stringify(obj);
    for (const [, c] of clients) {
        if (c.userId === userId && c.ws.readyState === c.ws.OPEN) c.ws.send(data);
    }
}

function broadcastToChannel(channelId, obj, exceptId) {
    const data = JSON.stringify(obj);
    for (const [cid, c] of clients) {
        if (cid === exceptId) continue;
        if (c.channelId === channelId && c.ws.readyState === c.ws.OPEN) c.ws.send(data);
    }
}

function broadcastToGuild(guildId, obj, exceptId) {
    const data = JSON.stringify(obj);
    for (const [cid, c] of clients) {
        if (cid === exceptId) continue;
        if (c.guildId === guildId && c.ws.readyState === c.ws.OPEN) c.ws.send(data);
    }
}

async function broadcastToGuildMembers(guildId, obj, exceptUserId) {
    const memberIds = new Set((await guildMembersStmt.all(guildId)).map(m => m.id));
    const data = JSON.stringify(obj);
    for (const [cid, c] of clients) {
        if (c.userId && memberIds.has(c.userId) && c.userId !== exceptUserId && c.ws.readyState === c.ws.OPEN) {
            c.ws.send(data);
        }
    }
}

// ================= BİLDİRİM MANTIĞI =================

// Metin içinde @kullaniciadi şeklinde geçen ve sunucu üyesi olan isimleri bulur.
// Büyük/küçük harf duyarsız, kelime sınırına dikkat eder (ör. "@ali2" -> "ali2").
function extractMentionedUserIds(text, guildMembers) {
    const mentioned = new Set();
    const nameToId = new Map(guildMembers.map(m => [m.username.toLowerCase(), m.id]));
    const matches = String(text || '').matchAll(/@([a-zA-Z0-9_]{1,32})/g);
    for (const m of matches) {
        const id = nameToId.get(m[1].toLowerCase());
        if (id) mentioned.add(id);
    }
    return mentioned;
}

// Bir kullanıcı için, kanal > sunucu > genel önceliğiyle nihai bildirim modunu
// hesaplar. Dönen değer her zaman 'all' | 'mentions_only' | 'none' olur
// (aradaki 'default' değerleri burada bir üst seviyeye devredilmiş olur).
async function resolveNotificationMode(userId, guildId, channelId) {
    const userPrefs = await getUserNotifPrefsStmt.get(userId);
    // Hiç kayıt yoksa varsayılanlar: bildirimler açık, sadece etiket değil (tüm mesajlar).
    const globalEnabled = userPrefs ? !!userPrefs.global_enabled : true;
    if (!globalEnabled) return 'none';
    const globalMode = (userPrefs && userPrefs.mentions_only) ? 'mentions_only' : 'all';

    const channelPref = await getChannelNotifPrefStmt.get(channelId, userId);
    if (channelPref && channelPref.mode !== 'default') return channelPref.mode;

    const guildPref = await getGuildNotifPrefStmt.get(guildId, userId);
    if (guildPref && guildPref.mode !== 'default') return guildPref.mode;

    return globalMode;
}

// Yeni bir mesaj geldiğinde, kanalı o an açık olsun ya da olmasın, sunucudaki
// diğer tüm üyelere (gönderen hariç) hafif bir 'notify' event'i yollar.
// İstemci, kendi bildirim ayarına ve pencere odağına göre gerçek bir OS
// bildirimi gösterip göstermeyeceğine kendi tarafında da karar verebilir;
// ama "kime gönderilsin" kararının asıl kaynağı burasıdır.
async function notifyGuildOfNewMessage({ guildId, guildName, channelId, channelName, senderUserId, senderName, senderAvatar, text }) {
    const members = await guildMembersStmt.all(guildId);
    const mentionedIds = extractMentionedUserIds(text, members);
    const preview = String(text || '').slice(0, 140);

    for (const member of members) {
        if (member.id === senderUserId) continue;
        const blocked = await isBlockedEitherWayStmt.get(member.id, senderUserId, senderUserId, member.id);
        if (blocked) continue;
        const mode = await resolveNotificationMode(member.id, guildId, channelId);
        const isMentioned = mentionedIds.has(member.id);
        const shouldNotify = mode === 'all' || (mode === 'mentions_only' && isMentioned);
        if (!shouldNotify) continue;

        const payload = {
            type: 'notify', kind: 'message',
            guildId, guildName, channelId, channelName,
            senderUserId, senderName, senderAvatar,
            text: preview, mentioned: isMentioned, ts: Date.now(),
        };
        for (const [, c] of clients) {
            if (c.userId === member.id && c.ws.readyState === c.ws.OPEN) c.ws.send(JSON.stringify(payload));
        }
    }
}

// Bir kullanıcı çevrimiçi olduğunda (ilk bağlantısı açıldığında), onunla ortak
// sunucusu olan ve bu bildirimi açmış kullanıcılara haber verir.
async function notifySharedGuildMembersOnline(userId, username) {
    const sharedUsers = await usersSharingGuildsWithStmt.all(userId);
    for (const u of sharedUsers) {
        const prefs = await getUserNotifPrefsStmt.get(u.id);
        if (!prefs || !prefs.shared_guild_online_enabled || !prefs.global_enabled) continue;
        const payload = { type: 'notify', kind: 'presence', userId, username, ts: Date.now() };
        for (const [, c] of clients) {
            if (c.userId === u.id && c.ws.readyState === c.ws.OPEN) c.ws.send(JSON.stringify(payload));
        }
    }
}

async function channelListPayload(guildId) {
    return { channels: await guildChannelsStmt.all(guildId), categories: await guildCategoriesStmt.all(guildId) };
}

async function broadcastChannelList(guildId) {
    broadcastToGuild(guildId, { type: 'channel-list', guildId, ...(await channelListPayload(guildId)) }, undefined);
}

// Üye listesi artık kişiye özel: aranızda bir engelleme varsa karşı tarafın
// avatarı/banner'ı bu listede sana (ve senin bilgilerin ona) gösterilmez.
// Kullanıcı listeden çıkarılmaz (üyeliği hâlâ gerçek), sadece profil bilgisi
// maskelenir ve "blocked" bayrağı istemciye "bu kişiyle etkileşim kapalı"
// demek için gönderilir.
async function memberListPayloadFor(guildId, viewerUserId) {
    const rows = await guildMembersStmt.all(guildId);
    const onlineIds = new Set([...clients.values()].filter(c => c.guildId === guildId).map(c => c.userId));
    const result = [];
    for (const r of rows) {
        let blocked = false;
        if (viewerUserId && r.id !== viewerUserId) {
            const b = await isBlockedEitherWayStmt.get(viewerUserId, r.id, r.id, viewerUserId);
            blocked = !!b;
        }
        result.push({
            userId: r.id,
            name: r.username,
            avatar: blocked ? null : (r.avatar || null),
            banner: blocked ? null : (r.banner || null),
            role: r.role,
            online: onlineIds.has(r.id),
            blocked,
        });
    }
    return result;
}

async function sendMemberListToGuild(guildId) {
    for (const [, c] of clients) {
        if (c.guildId === guildId && c.ws.readyState === c.ws.OPEN) {
            send(c.ws, { type: 'member-list', guildId, members: await memberListPayloadFor(guildId, c.userId) });
        }
    }
}

// Bir engelleme/engel kaldırma sonrası, iki kullanıcının ortak olduğu tüm
// sunucularda üye listesini yeniden gönderir (avatar maskeleme anında güncellensin diye).
async function refreshSharedGuildMemberLists(userIdA, userIdB) {
    const guildsA = await userGuilds.all(userIdA);
    const guildIdsB = new Set((await userGuilds.all(userIdB)).map(g => g.id));
    for (const g of guildsA) {
        if (guildIdsB.has(g.id)) await sendMemberListToGuild(g.id);
    }
}

function voiceUsersPayload(channelId) {
    return [...clients.values()]
        .filter(c => c.voiceChannelId === channelId)
        .map(c => ({ userId: c.userId, name: c.username, avatar: c.avatar || null, muted: c.muted }));
}

async function broadcastVoiceUsers(channelId) {
    const channel = await findChannelById.get(channelId);
    if (!channel) return;
    broadcastToGuild(channel.guild_id, { type: 'voice-users', channelId, users: voiceUsersPayload(channelId) }, undefined);
}

wss.on('connection', (ws) => {
    const id = nextId++;
    const state = { ws, userId: null, username: null, avatar: null, banner: null, guildId: null, channelId: null, voiceChannelId: null, muted: true, callPeerId: null, callInviteTo: null };
    clients.set(id, state);

    // Bağlantıyı canlı tutmak için nabız (heartbeat). Router/modem/NAT,
    // uzun süre sessiz kalan bağlantıları kendiliğinden kapatabiliyor;
    // düzenli ping göndermek hem bunu önlüyor hem de gerçekten kopan
    // bağlantıları erken tespit edip temizlememizi sağlıyor.
    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });

    ws.on('message', async (data, isBinary) => {
        if (isBinary) {
            // Bire bir DM araması aktifse ses sadece o kişiye gider.
            if (state.callPeerId) {
                const header = Buffer.alloc(2);
                header.writeUInt16LE(id, 0);
                const relay = Buffer.concat([header, data]);
                for (const [otherId, c] of clients) {
                    if (otherId === id) continue;
                    if (c.userId === state.callPeerId && c.ws.readyState === c.ws.OPEN) {
                        c.ws.send(relay, { binary: true });
                    }
                }
                return;
            }
            // Ham PCM ses verisi: sadece aynı sesli kanaldaki diğer kullanıcılara ilet.
            if (!state.voiceChannelId) return;
            const header = Buffer.alloc(2);
            header.writeUInt16LE(id, 0);
            const relay = Buffer.concat([header, data]);
            for (const [otherId, c] of clients) {
                if (otherId === id) continue;
                if (c.voiceChannelId === state.voiceChannelId && c.ws.readyState === c.ws.OPEN) {
                    c.ws.send(relay, { binary: true });
                }
            }
            return;
        }

        try {
            msg = JSON.parse(data.toString('utf8'));
        } catch {
            return;
        }

        // Rate limiting kontrolü
        if (rateLimitGeneral.isLimited(id)) {
            sendError(ws, 'Limit aşıldınız. Daha yavaş gönderen mesaj gönderin.');
            return;
        }

        // Message type validation
        if (!msg.type || !isValidMessageType(msg.type)) {
            console.warn(`[Güvenlik] Geçersiz message type: ${msg.type} (ID: ${id})`);
            return;
        }

        console.log('Gelen mesaj:', msg.type);

        try {
            // ---------- KİMLİK DOĞRULAMA ----------
            if (msg.type === 'register') {
                // Auth rate limiting
                const clientIp = ws._socket?.remoteAddress || id.toString();
                if (rateLimitAuth.isLimited(clientIp)) {
                    sendError(ws, 'Çok fazla kayıt denemesi. Lütfen daha sonra tekrar deneyin.');
                    return;
                }

                const username = validateUsername(msg.username);
                const password = String(msg.password || '');

                if (!username) {
                    sendError(ws, 'Geçersiz kullanıcı adı. 1-32 alfanümerik karakter ve alt çizgi kullanın.');
                    return;
                }
                if (!validatePassword(password)) {
                    sendError(ws, 'Şifre 6-128 karakter arasında olmalıdır.');
                    return;
                }

                try {
                    const hash = bcrypt.hashSync(password, 10);
                    await registerUserStmt.run(username, hash);
                    rateLimitAuth.reset(clientIp);
                } catch (e) {
                    console.error('[Register hatası]', e.message);
                    sendError(ws, 'Bu kullanıcı adı zaten kullanılıyor.');
                }
                return;
            }

            if (msg.type === 'login') {
                // Auth rate limiting
                const clientIp = ws._socket?.remoteAddress || id.toString();
                if (rateLimitAuth.isLimited(clientIp)) {
                    sendError(ws, 'Çok fazla giriş denemesi. Lütfen daha sonra tekrar deneyin.');
                    return;
                }

                const username = validateUsername(msg.username);
                const password = String(msg.password || '');

                if (!username || !password) {
                    sendError(ws, 'Kullanıcı adı ve şifre gereklidir.');
                    return;
                }

                try {
                    const user = await findUserByName.get(username);
                    if (!user || !bcrypt.compareSync(password, user.password)) {
                        sendError(ws, 'Geçersiz kimlik bilgileri.');
                        return;
                    }

                    const wasAlreadyOnline = [...clients.values()].some(c => c.userId === user.id);
                    state.userId = user.id;
                    state.username = user.username;
                    state.avatar = user.avatar || null;
                    state.banner = user.banner || null;
                    rateLimitAuth.reset(clientIp);

                    send(ws, { type: 'welcome', id, userId: user.id, username: user.username, avatar: user.avatar || null, banner: user.banner || null, createdAt: user.created_at || null });
                    send(ws, { type: 'guild-list', guilds: await userGuilds.all(user.id) });
                    console.log(`[+] ${user.username} giriş yaptı (#${id})`);

                    if (!wasAlreadyOnline) {
                        notifySharedGuildMembersOnline(user.id, user.username).catch(err => console.error('[Presence bildirimi gönderilemedi]', err));
                    }
                } catch (e) {
                    console.error('[Login hatası]', e.message);
                    sendError(ws, 'Giriş sırasında bir hata oluştu.');
                }
                return;
            }

            if (!state.userId) return; // giriş yapmadan hiçbir şey kabul etme

            // ---------- BİLDİRİM TERCİHLERİ ----------
            if (msg.type === 'get-notification-prefs') {
                const userPrefs = await getUserNotifPrefsStmt.get(state.userId);
                send(ws, {
                    type: 'notification-prefs',
                    global: userPrefs || { global_enabled: 1, mentions_only: 0, shared_guild_online_enabled: 0 },
                    guildOverrides: await getGuildNotifOverridesStmt.all(state.userId),
                    channelOverrides: await getChannelNotifOverridesStmt.all(state.userId),
                });
                return;
            }

            if (msg.type === 'set-notification-prefs') {
                await upsertUserNotifPrefsStmt.run(
                    state.userId,
                    msg.global_enabled ? 1 : 0,
                    msg.mentions_only ? 1 : 0,
                    msg.shared_guild_online_enabled ? 1 : 0
                );
                send(ws, { type: 'notification-prefs-saved' });
                return;
            }

            if (msg.type === 'set-guild-notification-pref') {
                const mode = ['default', 'all', 'mentions_only', 'none'].includes(msg.mode) ? msg.mode : 'default';
                await upsertGuildNotifPrefStmt.run(msg.guildId, state.userId, mode);
                send(ws, { type: 'notification-prefs-saved' });
                return;
            }

            if (msg.type === 'set-channel-notification-pref') {
                const mode = ['default', 'all', 'mentions_only', 'none'].includes(msg.mode) ? msg.mode : 'default';
                await upsertChannelNotifPrefStmt.run(msg.channelId, state.userId, mode);
                send(ws, { type: 'notification-prefs-saved' });
                return;
            }

            // ---------- ARKADAŞLIK ----------
            if (msg.type === 'get-friends') {
                send(ws, {
                    type: 'friends-data',
                    friends: await friendsListStmt.all(state.userId, state.userId, state.userId),
                    incoming: await incomingFriendRequestsStmt.all(state.userId),
                    outgoing: await outgoingFriendRequestsStmt.all(state.userId),
                    blocked: await blockedListStmt.all(state.userId),
                });
                return;
            }

            if (msg.type === 'send-friend-request') {
                const targetId = Number(msg.targetUserId);
                if (!targetId || targetId === state.userId) return;
                const target = await findUserById.get(targetId);
                if (!target) { send(ws, { type: 'error', message: 'Kullanıcı bulunamadı.' }); return; }

                const blocked = await isBlockedEitherWayStmt.get(state.userId, targetId, targetId, state.userId);
                if (blocked) { send(ws, { type: 'error', message: 'Bu kullanıcıyla aranızda bir engelleme var.' }); return; }

                const existing = await findFriendRequestBetweenStmt.get(state.userId, targetId, targetId, state.userId);
                if (existing) {
                    send(ws, { type: 'error', message: existing.status === 'accepted' ? 'Zaten arkadaşsınız.' : 'İstek zaten gönderilmiş.' });
                    return;
                }

                const inserted = await insertFriendRequestStmt.run(state.userId, targetId);
                send(ws, { type: 'friend-request-sent', targetUserId: targetId });
                sendToUser(targetId, { type: 'friend-request-received', from: { id: state.userId, username: state.username, avatar: state.avatar || null, requestId: inserted.lastInsertRowid } });
                return;
            }

            if (msg.type === 'accept-friend-request') {
                const request = await findFriendRequestByIdStmt.get(msg.requestId);
                if (!request || request.addressee_id !== state.userId) return;
                await acceptFriendRequestStmt.run(request.id);
                const requesterUser = await findUserById.get(request.requester_id);
                send(ws, { type: 'friend-request-accepted', friend: { id: request.requester_id, username: requesterUser ? requesterUser.username : '', avatar: requesterUser ? requesterUser.avatar : null } });
                sendToUser(request.requester_id, { type: 'friend-request-accepted', friend: { id: state.userId, username: state.username, avatar: state.avatar || null } });
                return;
            }

            if (msg.type === 'decline-friend-request') {
                const request = await findFriendRequestByIdStmt.get(msg.requestId);
                if (!request || request.addressee_id !== state.userId) return;
                await deleteFriendRequestByIdStmt.run(request.id);
                send(ws, { type: 'friend-request-declined', requestId: request.id });
                sendToUser(request.requester_id, { type: 'friend-request-cancelled', requestId: request.id });
                return;
            }

            if (msg.type === 'cancel-friend-request') {
                const request = await findFriendRequestByIdStmt.get(msg.requestId);
                if (!request || request.requester_id !== state.userId) return;
                await deleteFriendRequestByIdStmt.run(request.id);
                send(ws, { type: 'friend-request-cancelled', requestId: request.id });
                sendToUser(request.addressee_id, { type: 'friend-request-cancelled', requestId: request.id });
                return;
            }

            if (msg.type === 'remove-friend') {
                const friendId = Number(msg.friendUserId);
                await deleteFriendshipBetweenStmt.run(state.userId, friendId, friendId, state.userId);
                send(ws, { type: 'friend-removed', friendUserId: friendId });
                sendToUser(friendId, { type: 'friend-removed', friendUserId: state.userId });
                return;
            }

            // ---------- ENGELLEME ----------
            if (msg.type === 'block-user') {
                const targetId = Number(msg.targetUserId);
                if (!targetId || targetId === state.userId) return;
                await blockUserStmt.run(state.userId, targetId);
                await deleteFriendshipBetweenStmt.run(state.userId, targetId, targetId, state.userId);
                send(ws, { type: 'user-blocked', targetUserId: targetId });
                sendToUser(targetId, { type: 'friend-removed', friendUserId: state.userId });
                sendToUser(targetId, { type: 'dm-peer-blocked', peerId: state.userId });
                await refreshSharedGuildMemberLists(state.userId, targetId);
                return;
            }

            if (msg.type === 'unblock-user') {
                const targetId = Number(msg.targetUserId);
                await unblockUserStmt.run(state.userId, targetId);
                send(ws, { type: 'user-unblocked', targetUserId: targetId });
                await refreshSharedGuildMemberLists(state.userId, targetId);
                return;
            }

            // ---------- ÖZEL MESAJLAR (DM) ----------
            if (msg.type === 'get-dm-settings') {
                const row = await getDMSettingsStmt.get(state.userId);
                send(ws, {
                    type: 'dm-settings',
                    allowFrom: row ? row.allow_from : 'everyone',
                    allowKnown: row ? !!row.allow_known : true,
                });
                return;
            }

            if (msg.type === 'hide-dm-conversation') {
                const peerId = Number(msg.peerId);
                if (!peerId) return;
                const existing = await hasExistingDMConversation(state.userId, peerId);
                if (!existing) return;
                const convo = await getOrCreateDMConversation(state.userId, peerId);
                await hideDMConversationStmt.run(state.userId, convo.id);
                send(ws, { type: 'dm-conversation-hidden', peerId });
                return;
            }

            if (msg.type === 'set-dm-settings') {
                const allowFrom = ['everyone', 'friends', 'nobody'].includes(msg.allowFrom) ? msg.allowFrom : 'everyone';
                const allowKnown = msg.allowKnown !== false;
                await upsertDMSettingsStmt.run(state.userId, allowFrom, allowKnown ? 1 : 0);
                send(ws, { type: 'dm-settings-saved', allowFrom, allowKnown });
                return;
            }

            // ================= DM SESLİ ARAMA =================
            // Basit bire-bir çağrı sinyalleşmesi: davet -> kabul/red/iptal ->
            // aktif çağrı. Ses verisi, çağrı kabul edildikten sonra binary
            // mesaj yolunda (yukarıda) doğrudan karşı tarafa iletiliyor.
            if (msg.type === 'call-invite') {
                const peerId = Number(msg.peerId);
                if (!peerId || peerId === state.userId) return;
                if (state.callPeerId || state.callInviteTo) {
                    send(ws, { type: 'call-busy', peerId, self: true });
                    return;
                }
                const targetConns = [...clients.values()].filter(c => c.userId === peerId);
                if (targetConns.length === 0) {
                    send(ws, { type: 'call-unavailable', peerId });
                    return;
                }
                if (targetConns.some(c => c.callPeerId || c.callInviteTo)) {
                    send(ws, { type: 'call-busy', peerId });
                    return;
                }
                const permission = await canSendDM(state.userId, peerId);
                if (!permission.allowed) {
                    send(ws, { type: 'call-unavailable', peerId });
                    return;
                }
                state.callInviteTo = peerId;
                sendToUser(peerId, { type: 'call-incoming', fromId: state.userId, fromName: state.username, fromAvatar: state.avatar || null });
                return;
            }

            if (msg.type === 'call-cancel') {
                const peerId = Number(msg.peerId);
                if (state.callInviteTo === peerId) state.callInviteTo = null;
                sendToUser(peerId, { type: 'call-cancelled', peerId: state.userId });
                return;
            }

            if (msg.type === 'call-decline') {
                const peerId = Number(msg.peerId);
                for (const c of clients.values()) {
                    if (c.userId === peerId && c.callInviteTo === state.userId) c.callInviteTo = null;
                }
                sendToUser(peerId, { type: 'call-declined', peerId: state.userId });
                return;
            }

            if (msg.type === 'call-accept') {
                const peerId = Number(msg.peerId);
                const callerConns = [...clients.values()].filter(c => c.userId === peerId && c.callInviteTo === state.userId);
                if (callerConns.length === 0) {
                    send(ws, { type: 'call-cancelled', peerId });
                    return;
                }
                state.callPeerId = peerId;
                callerConns.forEach(c => { c.callInviteTo = null; c.callPeerId = state.userId; });
                sendToUser(peerId, { type: 'call-accepted', peerId: state.userId });
                send(ws, { type: 'call-accepted', peerId });
                return;
            }

            if (msg.type === 'call-end') {
                const peerId = state.callPeerId;
                state.callPeerId = null;
                state.callInviteTo = null;
                if (peerId) {
                    for (const c of clients.values()) {
                        if (c.userId === peerId) c.callPeerId = null;
                    }
                    sendToUser(peerId, { type: 'call-ended', peerId: state.userId });
                }
                return;
            }

            if (msg.type === 'get-dm-conversations') {
                const rows = await userDMConversationsStmt.all(state.userId, state.userId, state.userId, state.userId, state.userId, state.userId);
                const result = [];
                for (const r of rows) {
                    const peer = await findUserById.get(r.peer_id);
                    if (!peer) continue; // hesabı silinmiş kullanıcı
                    const blocked = await isBlockedEitherWayStmt.get(state.userId, r.peer_id, r.peer_id, state.userId);
                    result.push({
                        conversationId: r.conversation_id,
                        peerId: r.peer_id,
                        peerName: peer.username,
                        peerAvatar: blocked ? null : (peer.avatar || null),
                        blocked: !!blocked,
                        lastMessage: r.last_content || null,
                        lastMessageAt: r.last_ts ? new Date(r.last_ts).getTime() : null,
                        unreadCount: Number(r.unread_count) || 0,
                    });
                }
                result.sort((a, b) => (b.lastMessageAt || 0) - (a.lastMessageAt || 0));
                send(ws, { type: 'dm-conversations', conversations: result });
                return;
            }

            // Bir DM penceresi açıldığında geçmişi getirir ve "okundu" işaretler.
            // Konuşma hiç yoksa ve karşı tarafın ayarları izin veriyorsa yeni bir
            // konuşma oluşturur (henüz mesaj gönderilmemiş olsa bile).
            if (msg.type === 'open-dm') {
                const peerId = Number(msg.peerId);
                if (!peerId || peerId === state.userId) return;
                const peer = await findUserById.get(peerId);
                if (!peer) { send(ws, { type: 'dm-error', peerId, message: 'Kullanıcı bulunamadı.' }); return; }

                const blocked = await isBlockedEitherWayStmt.get(state.userId, peerId, peerId, state.userId);
                if (blocked) { send(ws, { type: 'dm-error', peerId, message: 'Bu kullanıcıyla mesajlaşamazsın.' }); return; }

                const existing = await hasExistingDMConversation(state.userId, peerId);
                if (!existing) {
                    const permission = await canSendDM(state.userId, peerId);
                    if (!permission.allowed) {
                        send(ws, { type: 'dm-error', peerId, message: 'Bu kullanıcının DM ayarları, henüz tanışmadığınız için yazmana izin vermiyor.' });
                        return;
                    }
                }

                const convo = await getOrCreateDMConversation(state.userId, peerId);
                await unhideDMConversationStmt.run(state.userId, convo.id);
                const history = (await dmHistoryStmt.all(convo.id)).reverse();
                await upsertDMReadStmt.run(convo.id, state.userId);
                send(ws, {
                    type: 'dm-history',
                    peerId,
                    peerName: peer.username,
                    peerAvatar: peer.avatar || null,
                    conversationId: convo.id,
                    messages: history.map(m => ({
                        id: m.id, senderId: m.sender_id, text: m.content,
                        ts: new Date(m.timestamp).getTime(),
                        editedAt: m.edited_at ? new Date(m.edited_at).getTime() : null,
                        attachment: m.attachment_data, attachmentType: m.attachment_type, attachmentName: m.attachment_name,
                    })),
                });
                send(ws, {
                    type: 'dm-pinned-messages',
                    peerId,
                    messages: (await pinnedDMMessagesStmt.all(convo.id)).map(m => ({
                        id: m.id, senderId: m.sender_id, text: m.content,
                        ts: new Date(m.timestamp).getTime(),
                    })),
                });
                return;
            }

            if (msg.type === 'dm-message') {
                const peerId = Number(msg.peerId);
                if (!peerId || peerId === state.userId) return;
                const text = String(msg.text || '').slice(0, 1000).trim();
                let attachmentData = null, attachmentType = null, attachmentName = null;
                if (msg.attachment && typeof msg.attachment === 'string' && msg.attachment.startsWith('data:')) {
                    if (msg.attachment.length > MAX_ATTACHMENT_DATAURL_LENGTH) {
                        send(ws, { type: 'error', message: 'Dosya çok büyük.' });
                        return;
                    }
                    attachmentData = msg.attachment;
                    attachmentType = String(msg.attachmentType || 'application/octet-stream').slice(0, 200);
                    attachmentName = String(msg.attachmentName || 'dosya').slice(0, 200);
                }
                if (!text && !attachmentData) return;

                const permission = await canSendDM(state.userId, peerId);
                if (!permission.allowed) {
                    const message = permission.reason === 'blocked'
                        ? 'Bu kullanıcıyla mesajlaşamazsın.'
                        : 'Bu kullanıcının DM ayarları buna izin vermiyor.';
                    send(ws, { type: 'dm-error', peerId, message });
                    return;
                }

                const convo = await getOrCreateDMConversation(state.userId, peerId);
                const info = await insertDMMessageStmt.run(convo.id, state.userId, text, attachmentData, attachmentType, attachmentName);
                await upsertDMReadStmt.run(convo.id, state.userId);
                await unhideDMConversationStmt.run(state.userId, convo.id);
                await unhideDMConversationStmt.run(peerId, convo.id);

                const basePayload = {
                    type: 'dm-message',
                    conversationId: convo.id,
                    id: info.lastInsertRowid,
                    senderId: state.userId,
                    senderName: state.username,
                    senderAvatar: state.avatar || null,
                    text,
                    ts: Date.now(),
                    attachment: attachmentData, attachmentType, attachmentName,
                };
                // Her iki tarafa da, kendi ekranında karşı tarafı temsil eden
                // "peerId" ile gönderiyoruz (gönderende peerId=alıcı, alıcıda peerId=gönderen).
                send(ws, { ...basePayload, peerId });
                sendToUser(peerId, { ...basePayload, peerId: state.userId });

                // Alıcıya, DM'i o an açık olsun ya da olmasın, hafif bir bildirim
                // eventi gönder. DM kişisel bir mesaj olduğu için (kanal
                // bildirimlerindeki "sadece etiketlenmeler" ayrımı yok), sadece
                // genel bildirimler açık mı diye bakıyoruz.
                const recipientPrefs = await getUserNotifPrefsStmt.get(peerId);
                const recipientNotifEnabled = recipientPrefs ? !!recipientPrefs.global_enabled : true;
                if (recipientNotifEnabled) {
                    sendToUser(peerId, {
                        type: 'notify', kind: 'dm',
                        senderUserId: state.userId, senderName: state.username, senderAvatar: state.avatar || null,
                        text: text.slice(0, 140) || (attachmentData ? '📎 Dosya gönderildi' : ''), ts: Date.now(),
                    });
                }
                return;
            }

            if (msg.type === 'dm-edit-message') {
                const message = await findDMMessageById.get(msg.messageId);
                if (!message) return;
                if (message.sender_id !== state.userId) {
                    send(ws, { type: 'error', message: 'Sadece kendi mesajını düzenleyebilirsin.' });
                    return;
                }
                const text = String(msg.text || '').slice(0, 1000).trim();
                if (!text) return;
                await updateDMMessageStmt.run(text, msg.messageId);
                const convo = await findDMConversationById.get(message.conversation_id);
                const editedAt = new Date().toISOString();
                const payload = { type: 'dm-message-edited', id: msg.messageId, text, editedAt };
                if (convo) {
                    sendToUser(convo.user_a, payload);
                    sendToUser(convo.user_b, payload);
                } else {
                    send(ws, payload);
                }
                return;
            }

            if (msg.type === 'dm-delete-message') {
                const message = await findDMMessageById.get(msg.messageId);
                if (!message) return;
                if (message.sender_id !== state.userId) {
                    send(ws, { type: 'error', message: 'Bu mesajı silme yetkin yok.' });
                    return;
                }
                await deleteDMMessageStmt.run(msg.messageId);
                const convo = await findDMConversationById.get(message.conversation_id);
                const payload = { type: 'dm-message-deleted', id: msg.messageId };
                if (convo) {
                    sendToUser(convo.user_a, payload);
                    sendToUser(convo.user_b, payload);
                } else {
                    send(ws, payload);
                }
                return;
            }

            if (msg.type === 'dm-pin-message' || msg.type === 'dm-unpin-message') {
                const message = await findDMMessageById.get(msg.messageId);
                if (!message) return;
                const convo = await findDMConversationById.get(message.conversation_id);
                if (!convo) return;
                // DM'de sunucudaki gibi rol hiyerarşisi yok; sohbetin iki
                // tarafından biri olmak yeterli (sunucudaki owner/admin
                // kısıtının DM karşılığı burada "bu sohbetin bir tarafı olmak").
                if (convo.user_a !== state.userId && convo.user_b !== state.userId) {
                    send(ws, { type: 'error', message: 'Bu mesajı sabitleme yetkin yok.' });
                    return;
                }
                if (msg.type === 'dm-pin-message') await pinDMMessageStmt.run(msg.messageId);
                else await unpinDMMessageStmt.run(msg.messageId);
                const pinnedMessages = (await pinnedDMMessagesStmt.all(convo.id)).map(m => ({
                    id: m.id, senderId: m.sender_id, text: m.content,
                    ts: new Date(m.timestamp).getTime(),
                }));
                sendToUser(convo.user_a, { type: 'dm-pinned-messages', peerId: convo.user_b, messages: pinnedMessages });
                sendToUser(convo.user_b, { type: 'dm-pinned-messages', peerId: convo.user_a, messages: pinnedMessages });
                return;
            }

            if (msg.type === 'mark-dm-read') {
                const peerId = Number(msg.peerId);
                if (!peerId) return;
                const convo = await getOrCreateDMConversation(state.userId, peerId);
                await upsertDMReadStmt.run(convo.id, state.userId);
                return;
            }

            // ---------- HESAP SİLME ----------
            if (msg.type === 'delete-account') {
                const user = await findUserById.get(state.userId);
                if (!user || !bcrypt.compareSync(String(msg.password || ''), user.password)) {
                    send(ws, { type: 'error', message: 'Şifre yanlış.' });
                    return;
                }

                const myGuilds = await ownedGuildsStmt.all(state.userId);
                for (const guild of myGuilds) {
                    const others = await otherGuildMembersOrderedStmt.all(guild.id, state.userId);
                    if (others.length > 0) {
                        const newOwner = others[0];
                        await transferGuildOwnerStmt.run(newOwner.user_id, guild.id);
                        await setMemberRoleForTransferStmt.run(guild.id, newOwner.user_id);
                        await sendMemberListToGuild(guild.id);
                        for (const [, c] of clients) {
                            if (c.userId === newOwner.user_id) send(c.ws, { type: 'guild-list', guilds: await userGuilds.all(c.userId) });
                        }
                    } else {
                        await deleteGuildMessagesStmt.run(guild.id);
                        await deleteGuildChannelsStmt.run(guild.id);
                        await deleteGuildMembersStmt.run(guild.id);
                        await deleteGuildBansStmt.run(guild.id);
                        await deleteGuildStmt.run(guild.id);
                    }
                }

                // Üyesi olduğu (sahibi olmadığı) sunucuların üye/kanal listelerini güncellemek için önce ilgili sunucuları not al.
                const myMemberships = await userGuilds.all(state.userId);

                await anonymizeUserMessagesStmt.run(state.userId);
                await deleteAllMembershipsForUserStmt.run(state.userId);
                await deleteFriendRequestsInvolvingStmt.run(state.userId, state.userId);
                await deleteBlocksInvolvingStmt.run(state.userId, state.userId);
                await deleteUserNotifPrefsStmt.run(state.userId);
                await deleteGuildNotifPrefsForUserStmt.run(state.userId);
                await deleteChannelNotifPrefsForUserStmt.run(state.userId);
                await deleteDMMessagesForUserStmt.run(state.userId, state.userId);
                await deleteDMReadsForUserStmt.run(state.userId, state.userId);
                await deleteDMConversationsForUserStmt.run(state.userId, state.userId);
                await deleteDMSettingsForUserStmt.run(state.userId);
                await deleteUserByIdStmt.run(state.userId);

                for (const g of myMemberships) {
                    await sendMemberListToGuild(g.id).catch(() => { });
                }

                send(ws, { type: 'account-deleted' });
                const deletedUserId = state.userId;
                state.userId = null;
                state.username = null;
                console.log(`[!] Kullanıcı hesabını sildi (#${deletedUserId})`);
                ws.close();
                return;
            }

            // ---------- PROFİL GÜNCELLEME ----------
            if (msg.type === 'update-profile') {
                let newUsername = state.username;
                if (typeof msg.username === 'string') {
                    const uname = msg.username.trim().slice(0, 32);
                    if (uname && uname !== state.username) {
                        const clash = await findUserByName.get(uname);
                        if (clash && clash.id !== state.userId) {
                            send(ws, { type: 'error', message: 'Bu kullanıcı adı zaten alınmış.' });
                            return;
                        }
                        await updateUsernameStmt.run(uname, state.userId);
                        newUsername = uname;
                    }
                }
                if (typeof msg.newPassword === 'string' && msg.newPassword.length > 0) {
                    const currentUser = await findUserById.get(state.userId);
                    const oldPassword = String(msg.oldPassword || '');
                    if (!currentUser || !bcrypt.compareSync(oldPassword, currentUser.password)) {
                        send(ws, { type: 'error', message: 'Eski şifre yanlış.' });
                        return;
                    }
                    const hash = bcrypt.hashSync(msg.newPassword, 10);
                    await updatePasswordStmt.run(hash, state.userId);
                }
                let newAvatar = state.avatar;
                if (typeof msg.avatar === 'string') {
                    if (msg.avatar.length > 500000) {
                        send(ws, { type: 'error', message: 'Profil resmi çok büyük.' });
                        return;
                    }
                    await updateAvatarStmt.run(msg.avatar, state.userId);
                    newAvatar = msg.avatar;
                }
                let newBanner = state.banner;
                if (typeof msg.banner === 'string') {
                    if (msg.banner.length > 700000) {
                        send(ws, { type: 'error', message: 'Kapak resmi çok büyük.' });
                        return;
                    }
                    await updateBannerStmt.run(msg.banner, state.userId);
                    newBanner = msg.banner;
                }
                state.username = newUsername;
                state.avatar = newAvatar;
                state.banner = newBanner;
                send(ws, { type: 'profile-updated', username: newUsername, avatar: newAvatar, banner: newBanner });
                if (state.guildId) await sendMemberListToGuild(state.guildId);
                return;
            }

            // ---------- SUNUCU (GUILD) YÖNETİMİ ----------
            if (msg.type === 'create-guild') {
                const name = sanitizeText(msg.name, 50);
                if (!name || name.length < 1) {
                    sendError(ws, 'Sunucu adı boş olamaz.');
                    return;
                }
                try {
                    await createGuildWithDefaults(name, state.userId);
                    send(ws, { type: 'guild-list', guilds: await userGuilds.all(state.userId) });
                } catch (e) {
                    console.error('[Guild oluştur hata]', e.message);
                    sendError(ws, 'Sunucu oluşturulurken hata oluştu.');
                }
                return;
            }

            // ---------- ANASAYFA: KEŞFET / ARA ----------
            if (msg.type === 'discover') {
                send(ws, { type: 'discover-guilds', guilds: await discoverGuildsStmt.all() });
                return;
            }

            if (msg.type === 'search') {
                const qRaw = String(msg.query || '').trim().slice(0, 100);
                if (!qRaw) { send(ws, { type: 'search-results', query: '', guilds: [], users: [] }); return; }
                const q = qRaw.replace(/^#/, ''); // #sohbet gibi aramalarda # işaretini yok say
                const like = `%${q}%`;
                const guildResults = await searchGuildsStmt.all(like, like);
                const rawUsers = (await searchUsersStmt.all(like)).filter(u => u.id !== state.userId);
                const userResults = [];
                for (const u of rawUsers) {
                    const blocked = await isBlockedEitherWayStmt.get(state.userId, u.id, u.id, state.userId);
                    userResults.push({ id: u.id, username: u.username, avatar: blocked ? null : (u.avatar || null), blocked: !!blocked });
                }
                send(ws, { type: 'search-results', query: qRaw, guilds: guildResults, users: userResults });
                return;
            }

            if (msg.type === 'join-guild-direct') {
                const guild = await findGuildById.get(msg.guildId);
                if (!guild) { send(ws, { type: 'error', message: 'Sunucu bulunamadı.' }); return; }
                const ban = await findBan.get(msg.guildId, state.userId);
                if (ban) { send(ws, { type: 'error', message: 'Bu sunucudan yasaklandığın için katılamazsın.' }); return; }
                const already = await findMembership.get(msg.guildId, state.userId);
                if (!already) {
                    await addMember.run(msg.guildId, state.userId, 'member');
                    await sendMemberListToGuild(msg.guildId);
                }
                send(ws, { type: 'guild-list', guilds: await userGuilds.all(state.userId) });
                return;
            }

            if (msg.type === 'join-guild') {
                const code = String(msg.inviteCode || '').trim().toLowerCase();
                const guild = await findGuildByInvite.get(code);
                if (!guild) { send(ws, { type: 'error', message: 'Geçersiz davet kodu.' }); return; }
                const ban = await findBan.get(guild.id, state.userId);
                if (ban) { send(ws, { type: 'error', message: 'Bu sunucudan yasaklandığın için katılamazsın.' }); return; }
                await addMember.run(guild.id, state.userId, 'member');
                send(ws, { type: 'guild-list', guilds: await userGuilds.all(state.userId) });
                await sendMemberListToGuild(guild.id);
                return;
            }

            if (msg.type === 'select-guild') {
                const membership = await findMembership.get(msg.guildId, state.userId);
                if (!membership) { send(ws, { type: 'error', message: 'Bu sunucunun üyesi değilsin.' }); return; }
                state.guildId = msg.guildId;
                state.channelId = null;
                const payload = await channelListPayload(msg.guildId);
                send(ws, { type: 'channel-list', guildId: msg.guildId, ...payload });
                send(ws, { type: 'member-list', guildId: msg.guildId, members: await memberListPayloadFor(msg.guildId, state.userId) });
                // Sunucuya ilk girişte, o an dolu olan sesli kanalların katılımcı
                // listesini de gönder (yoksa sadece bir sonraki giriş/çıkışta güncellenirdi).
                payload.channels.filter(c => c.type === 'voice').forEach(c => {
                    send(ws, { type: 'voice-users', channelId: c.id, users: voiceUsersPayload(c.id) });
                });
                return;
            }

            // ---------- SUNUCU AYARLARI (sadece sahip düzenler, üyeler görür) ----------
            if (msg.type === 'update-guild') {
                const guild = await findGuildById.get(msg.guildId);
                if (!guild) return;
                const membership = await findMembership.get(msg.guildId, state.userId);
                if (!membership || membership.role !== 'owner') {
                    send(ws, { type: 'error', message: 'Bu işlem için sunucu sahibi olmalısın.' });
                    return;
                }
                const name = (typeof msg.name === 'string' && msg.name.trim()) ? msg.name.trim().slice(0, 50) : guild.name;
                const description = typeof msg.description === 'string' ? msg.description.trim().slice(0, 300) : (guild.description || '');
                let avatar = guild.avatar;
                if (typeof msg.avatar === 'string') {
                    if (msg.avatar.length > 500000) { send(ws, { type: 'error', message: 'Sunucu resmi çok büyük.' }); return; }
                    avatar = msg.avatar;
                }
                let banner = guild.banner;
                if (typeof msg.banner === 'string') {
                    if (msg.banner.length > 700000) { send(ws, { type: 'error', message: 'Sunucu banner\'ı çok büyük.' }); return; }
                    banner = msg.banner;
                }
                const isPrivate = typeof msg.isPrivate === 'boolean' ? (msg.isPrivate ? 1 : 0) : (guild.is_private || 0);
                await updateGuildStmt.run(name, avatar, description, banner, isPrivate, msg.guildId);
                const updated = await findGuildById.get(msg.guildId);
                await broadcastToGuildMembers(msg.guildId, { type: 'guild-updated', guild: updated }, undefined);
                send(ws, { type: 'guild-updated', guild: updated });
                return;
            }

            if (msg.type === 'kick-member') {
                if (!isValidGuildId(msg.guildId) || !isValidUserId(msg.userId)) {
                    sendError(ws, 'Geçersiz parametre.');
                    return;
                }
                try {
                    const membership = await findMembership.get(msg.guildId, state.userId);
                    if (!isOwnerOrAdmin(membership)) {
                        sendError(ws, 'Üye atmak için yetkin yok.');
                        return;
                    }
                    if (msg.userId === state.userId) {
                        sendError(ws, 'Kendini atamazsın.');
                        return;
                    }
                    const target = await findMembership.get(msg.guildId, msg.userId);
                    if (!target) {
                        sendError(ws, 'Üye bulunamadı.');
                        return;
                    }
                    if (target.role === 'owner') {
                        sendError(ws, 'Sunucu sahibi atılamaz.');
                        return;
                    }
                    if (membership.role === 'admin' && target.role !== 'member') {
                        sendError(ws, 'Sadece normal üyeleri sunucudan atabilirsin.');
                        return;
                    }
                    await removeMemberStmt.run(msg.guildId, msg.userId);
                    const kickDurationMinutes = Number(msg.durationMinutes) || 0;
                    if (kickDurationMinutes > 0 && kickDurationMinutes <= 10080) { // Max 7 gün
                        const targetUser = await findUserById.get(msg.userId);
                        const expiresAt = new Date(Date.now() + kickDurationMinutes * 60 * 1000);
                        await insertBan.run(msg.guildId, msg.userId, targetUser ? targetUser.username : '?', expiresAt);
                    }
                    await sendMemberListToGuild(msg.guildId);
                    for (const [cid, c] of clients) {
                        if (c.userId === msg.userId) {
                            if (c.voiceChannelId) {
                                const ch = await findChannelById.get(c.voiceChannelId);
                                if (ch && ch.guild_id === msg.guildId) {
                                    const oldVoiceChannelId = c.voiceChannelId;
                                    c.voiceChannelId = null;
                                    broadcastToChannel(oldVoiceChannelId, { type: 'voice-users', channelId: oldVoiceChannelId, users: voiceUsersPayload(oldVoiceChannelId) }, undefined);
                                }
                            }
                            send(c.ws, { type: 'kicked', guildId: msg.guildId });
                            send(c.ws, { type: 'guild-list', guilds: await userGuilds.all(c.userId) });
                            if (c.guildId === msg.guildId) { c.guildId = null; c.channelId = null; }
                        }
                    }
                } catch (e) {
                    console.error('[Kick member hata]', e.message);
                    sendError(ws, 'Üye atılırken hata oluştu.');
                }
                return;
            }

            if (msg.type === 'ban-member') {
                if (!isValidGuildId(msg.guildId) || !isValidUserId(msg.userId)) {
                    sendError(ws, 'Geçersiz parametre.');
                    return;
                }
                try {
                    const membership = await findMembership.get(msg.guildId, state.userId);
                    if (!isOwnerOrAdmin(membership)) {
                        sendError(ws, 'Yasaklamak için yetkin yok.');
                        return;
                    }
                    if (msg.userId === state.userId) { sendError(ws, 'Kendini yasaklayamazsın.'); return; }
                    const target = await findMembership.get(msg.guildId, msg.userId);
                    if (target && target.role === 'owner') {
                        sendError(ws, 'Sunucu sahibi yasaklanamaz.');
                        return;
                    }
                    if (membership.role === 'admin' && target && target.role !== 'member') {
                        sendError(ws, 'Sadece normal üyeleri yasaklayabilirsin.');
                        return;
                    }
                    const targetUser = await findUserById.get(msg.userId);
                    const banDurationMinutes = Number(msg.durationMinutes) || null;
                    const expiresAt = banDurationMinutes && banDurationMinutes > 0 ? new Date(Date.now() + Math.min(banDurationMinutes, 10080) * 60 * 1000) : null;
                    await insertBan.run(msg.guildId, msg.userId, targetUser ? targetUser.username : '?', expiresAt);
                    await removeMemberStmt.run(msg.guildId, msg.userId);
                    console.log(`[Yasak] ${targetUser?.username || msg.userId} sunucudan yasaklandı`);
                    await sendMemberListToGuild(msg.guildId);
                    for (const [cid, c] of clients) {
                        if (c.userId === msg.userId && c.guildId === msg.guildId) {
                            send(c.ws, { type: 'banned', guildId: msg.guildId });
                            send(c.ws, { type: 'guild-list', guilds: await userGuilds.all(c.userId) });
                            c.guildId = null; c.channelId = null;
                        }
                    }
                } catch (e) {
                    console.error('[Ban member hata]', e.message);
                    sendError(ws, 'Üye yasaklanırken hata oluştu.');
                }
                return;
            }

            if (msg.type === 'unban-member') {
                if (!isValidGuildId(msg.guildId) || !isValidUserId(msg.userId)) {
                    sendError(ws, 'Geçersiz parametre.');
                    return;
                }
                try {
                    const membership = await findMembership.get(msg.guildId, state.userId);
                    if (!isOwnerOrAdmin(membership)) {
                        sendError(ws, 'Yasağı kaldırmak için yetkin yok.');
                        return;
                    }
                    await removeBan.run(msg.guildId, msg.userId);
                    send(ws, { type: 'ban-list', guildId: msg.guildId, bans: await guildBansStmt.all(msg.guildId) });
                } catch (e) {
                    console.error('[Unban member hata]', e.message);
                    sendError(ws, 'Yasak kaldırılırken hata oluştu.');
                }
                return;
            }

            if (msg.type === 'list-bans') {
                const membership = await findMembership.get(msg.guildId, state.userId);
                if (!membership || (membership.role !== 'owner' && membership.role !== 'admin')) {
                    send(ws, { type: 'error', message: 'Yasaklı listesini görmek için yetkin yok.' });
                    return;
                }
                send(ws, { type: 'ban-list', guildId: msg.guildId, bans: await guildBansStmt.all(msg.guildId) });
                return;
            }

            if (msg.type === 'set-member-role') {
                const membership = await findMembership.get(msg.guildId, state.userId);
                if (!membership || membership.role !== 'owner') {
                    send(ws, { type: 'error', message: 'Rol vermek için sunucu sahibi olmalısın.' });
                    return;
                }
                if (msg.userId === state.userId) { send(ws, { type: 'error', message: 'Kendi rolünü değiştiremezsin.' }); return; }
                const target = await findMembership.get(msg.guildId, msg.userId);
                if (!target || target.role === 'owner') {
                    send(ws, { type: 'error', message: 'Bu üyenin rolü değiştirilemez.' });
                    return;
                }
                const role = msg.role === 'admin' ? 'admin' : 'member';
                await setMemberRoleStmt.run(role, msg.guildId, msg.userId);
                await sendMemberListToGuild(msg.guildId);
                for (const [cid, c] of clients) {
                    if (c.userId === msg.userId) send(c.ws, { type: 'guild-list', guilds: await userGuilds.all(c.userId) });
                }
                return;
            }

            if (msg.type === 'delete-guild') {
                if (!isValidGuildId(msg.guildId)) {
                    sendError(ws, 'Geçersiz sunucu ID.');
                    return;
                }
                try {
                    const membership = await findMembership.get(msg.guildId, state.userId);
                    if (!isOwner(membership)) {
                        sendError(ws, 'Sunucuyu silmek için sahibi olmalısın.');
                        return;
                    }
                    const memberIds = (await guildMembersStmt.all(msg.guildId)).map(m => m.id);
                    await deleteGuildMessagesStmt.run(msg.guildId);
                    await deleteGuildChannelsStmt.run(msg.guildId);
                    await deleteGuildMembersStmt.run(msg.guildId);
                    await deleteGuildBansStmt.run(msg.guildId);
                    await deleteGuildStmt.run(msg.guildId);
                    for (const [cid, c] of clients) {
                        if (c.guildId === msg.guildId) { c.guildId = null; c.channelId = null; }
                        if (c.voiceChannelId) {
                            const ch = await findChannelById.get(c.voiceChannelId);
                            if (!ch) c.voiceChannelId = null;
                        }
                        if (c.userId && memberIds.includes(c.userId)) {
                            send(c.ws, { type: 'guild-deleted', guildId: msg.guildId });
                            send(c.ws, { type: 'guild-list', guilds: await userGuilds.all(c.userId) });
                        }
                    }
                } catch (e) {
                    console.error('[Sunucu sil hata]', e.message);
                    sendError(ws, 'Sunucu silinirken hata oluştu.');
                }
                return;
            }

            // ---------- KATEGORİ YÖNETİMİ (sahip + yönetici) ----------
            if (msg.type === 'create-category') {
                const membership = await findMembership.get(msg.guildId, state.userId);
                if (!canManageChannels(membership)) {
                    send(ws, { type: 'error', message: 'Kategori oluşturmak için yetkin yok.' });
                    return;
                }
                const name = String(msg.name || '').trim().slice(0, 40);
                if (!name) return;
                await insertCategory.run(msg.guildId, name, 0);
                await broadcastChannelList(msg.guildId);
                return;
            }

            if (msg.type === 'delete-category') {
                const category = await findCategoryById.get(msg.categoryId);
                if (!category) return;
                const membership = await findMembership.get(category.guild_id, state.userId);
                if (!canManageChannels(membership)) {
                    send(ws, { type: 'error', message: 'Kategori silmek için yetkin yok.' });
                    return;
                }
                await uncategorizeChannelsStmt.run(msg.categoryId);
                await deleteCategoryStmt.run(msg.categoryId);
                await broadcastChannelList(category.guild_id);
                return;
            }

            // ---------- KANAL YÖNETİMİ (sahip + yönetici) ----------
            if (msg.type === 'create-channel') {
                try {
                    const membership = await findMembership.get(msg.guildId, state.userId);
                    if (!canManageChannels(membership)) {
                        sendError(ws, 'Kanal oluşturmak için yetkin yok.');
                        return;
                    }
                    const name = sanitizeText(msg.name, 40);
                    if (!name || name.length < 1) {
                        sendError(ws, 'Kanal adı boş olamaz.');
                        return;
                    }
                    const chType = msg.channelType === 'voice' ? 'voice' : 'text';
                    let categoryId = null;
                    if (msg.categoryId) {
                        const cat = await findCategoryById.get(msg.categoryId);
                        if (cat && cat.guild_id === msg.guildId) categoryId = cat.id;
                    }
                    await insertChannel.run(msg.guildId, name, chType, 0, categoryId);
                    await broadcastChannelList(msg.guildId);
                } catch (e) {
                    console.error('[Kanal oluştur hata]', e.message);
                    sendError(ws, 'Kanal oluşturulurken hata oluştu.');
                }
                return;
            }

            if (msg.type === 'delete-channel') {
                const channel = await findChannelById.get(msg.channelId);
                if (!channel) return;
                const membership = await findMembership.get(channel.guild_id, state.userId);
                if (!canManageChannels(membership)) {
                    send(ws, { type: 'error', message: 'Kanal silmek için yetkin yok.' });
                    return;
                }
                await deleteChannelMessages.run(msg.channelId);
                await deleteChannelStmt.run(msg.channelId);
                await broadcastChannelList(channel.guild_id);
                return;
            }

            // ---------- METİN KANALI SEÇME / SOHBET ----------
            if (msg.type === 'select-channel') {
                const channel = await findChannelById.get(msg.channelId);
                if (!channel) return;
                const membership = await findMembership.get(channel.guild_id, state.userId);
                if (!membership) return;
                state.channelId = msg.channelId;
                if (channel.type === 'text') {
                    const history = (await channelHistoryStmt.all(msg.channelId)).reverse();
                    send(ws, { type: 'history', channelId: msg.channelId, messages: history });
                    send(ws, { type: 'pinned-messages', channelId: msg.channelId, messages: await pinnedMessagesStmt.all(msg.channelId) });
                }
                return;
            }

            if (msg.type === 'chat') {
                if (!state.channelId) return;
                const text = sanitizeText(msg.text, 2000);
                let attachmentData = null, attachmentType = null, attachmentName = null;

                if (msg.attachment && typeof msg.attachment === 'string' && msg.attachment.startsWith('data:')) {
                    if (msg.attachment.length > MAX_ATTACHMENT_DATAURL_LENGTH) {
                        sendError(ws, 'Dosya çok büyük.');
                        return;
                    }
                    attachmentData = msg.attachment;
                    attachmentType = String(msg.attachmentType || 'application/octet-stream').slice(0, 100);
                    // MIME type validation
                    if (!/^[a-z]+\/[a-z0-9+\-.]+$/.test(attachmentType)) {
                        attachmentType = 'application/octet-stream';
                    }
                    attachmentName = sanitizeText(msg.attachmentName || 'dosya', 200);
                }

                if (!text && !attachmentData) return;

                try {
                    const info = await insertMessage.run(state.channelId, state.username, state.userId, text, attachmentData, attachmentType, attachmentName);
                    broadcastToChannel(state.channelId, {
                        type: 'chat', channelId: state.channelId, id: info.lastInsertRowid, userId: state.userId, name: state.username,
                        avatar: state.avatar || null, text, ts: Date.now(),
                        attachment: attachmentData, attachmentType, attachmentName,
                    }, undefined);

                    // Kanalı o an açık olmasa bile, sunucudaki ilgili üyelere bildirim gönder.
                    const channelForNotif = await findChannelById.get(state.channelId);
                    if (channelForNotif) {
                        const guildForNotif = await findGuildById.get(channelForNotif.guild_id);
                        notifyGuildOfNewMessage({
                            guildId: channelForNotif.guild_id,
                            guildName: guildForNotif ? guildForNotif.name : '',
                            channelId: state.channelId,
                            channelName: channelForNotif.name,
                            senderUserId: state.userId,
                            senderName: state.username,
                            senderAvatar: state.avatar || null,
                            text: text || (attachmentData ? '📎 Dosya gönderildi' : ''),
                        }).catch(err => console.error('[Bildirim gönderilemedi]', err));
                    }
                } catch (e) {
                    console.error('[Mesaj gönder hata]', e.message);
                    sendError(ws, 'Mesaj gönderilemedi.');
                }
                return;
            }

            if (msg.type === 'edit-message') {
                const message = await findMessageById.get(msg.messageId);
                if (!message) return;
                const channel = await findChannelById.get(message.channel_id);
                if (!channel) return;
                const membership = await findMembership.get(channel.guild_id, state.userId);
                if (!membership) return;
                if (message.user_id !== state.userId && message.sender !== state.username) {
                    send(ws, { type: 'error', message: 'Sadece kendi mesajını düzenleyebilirsin.' });
                    return;
                }
                const text = String(msg.text || '').slice(0, 1000).trim();
                if (!text) return;
                await updateMessageStmt.run(text, msg.messageId);
                broadcastToChannel(message.channel_id, { type: 'message-edited', channelId: message.channel_id, id: msg.messageId, text, editedAt: new Date().toISOString() }, undefined);
                return;
            }

            if (msg.type === 'delete-message') {
                const message = await findMessageById.get(msg.messageId);
                if (!message) return;
                const channel = await findChannelById.get(message.channel_id);
                if (!channel) return;
                const membership = await findMembership.get(channel.guild_id, state.userId);
                if (!membership) return;
                const isOwnMessage = message.user_id === state.userId || message.sender === state.username;
                const canModerate = membership.role === 'owner' || membership.role === 'admin';
                if (!isOwnMessage && !canModerate) {
                    send(ws, { type: 'error', message: 'Bu mesajı silme yetkin yok.' });
                    return;
                }
                await deleteMessageStmt.run(msg.messageId);
                broadcastToChannel(message.channel_id, { type: 'message-deleted', channelId: message.channel_id, id: msg.messageId }, undefined);
                return;
            }

            if (msg.type === 'pin-message' || msg.type === 'unpin-message') {
                const message = await findMessageById.get(msg.messageId);
                if (!message) return;
                const channel = await findChannelById.get(message.channel_id);
                if (!channel) return;
                const membership = await findMembership.get(channel.guild_id, state.userId);
                if (!membership || (membership.role !== 'owner' && membership.role !== 'admin')) {
                    send(ws, { type: 'error', message: 'Mesaj sabitlemek için yetkin yok.' });
                    return;
                }
                if (msg.type === 'pin-message') await pinMessageStmt.run(msg.messageId);
                else await unpinMessageStmt.run(msg.messageId);
                broadcastToChannel(message.channel_id, { type: 'pinned-messages', channelId: message.channel_id, messages: await pinnedMessagesStmt.all(message.channel_id) }, undefined);
                return;
            }

            // ---------- SESLİ KANAL ----------
            if (msg.type === 'voice-join') {
                const channel = await findChannelById.get(msg.channelId);
                if (!channel || channel.type !== 'voice') return;
                const membership = await findMembership.get(channel.guild_id, state.userId);
                if (!membership) return;
                const prevVoice = state.voiceChannelId;
                state.voiceChannelId = msg.channelId;
                state.muted = false;
                if (prevVoice && prevVoice !== msg.channelId) await broadcastVoiceUsers(prevVoice);
                await broadcastVoiceUsers(msg.channelId);
                return;
            }

            if (msg.type === 'voice-leave') {
                const prev = state.voiceChannelId;
                state.voiceChannelId = null;
                if (prev) await broadcastVoiceUsers(prev);
                return;
            }

            if (msg.type === 'mute-state') {
                state.muted = !!msg.muted;
                if (state.voiceChannelId) await broadcastVoiceUsers(state.voiceChannelId);
                return;
            }
        } catch (err) {
            // Tek bir mesajda hata olması TÜM sunucuyu çökertmesin diye buradayız.
            console.error('[Mesaj işlenirken hata]', msg && msg.type, err);
            try {
                send(ws, { type: 'error', message: 'Sunucuda beklenmeyen bir hata oluştu, lütfen tekrar dene.' });
            } catch { /* bağlantı zaten kapanmış olabilir */ }
        }
    });

    ws.on('close', async () => {
        try {
            const prevGuild = state.guildId;
            const prevVoice = state.voiceChannelId;
            if (state.callPeerId) {
                for (const c of clients.values()) if (c.userId === state.callPeerId) c.callPeerId = null;
                sendToUser(state.callPeerId, { type: 'call-ended', peerId: state.userId });
            }
            if (state.callInviteTo) {
                sendToUser(state.callInviteTo, { type: 'call-cancelled', peerId: state.userId });
            }
            clients.delete(id);
            if (prevGuild) await sendMemberListToGuild(prevGuild);
            if (prevVoice) await broadcastVoiceUsers(prevVoice);
            if (state.username) console.log(`[-] ${state.username} ayrıldı (#${id})`);
        } catch (err) {
            console.error('[Bağlantı kapanırken hata]', err);
        }
    });

    ws.on('error', () => { });
});

// Her 30 saniyede bir tüm bağlantılara ping gönder. Bir önceki ping'e
// hâlâ cevap (pong) vermemiş bağlantı gerçekten kopmuş demektir, onu kapatıp
// temizliyoruz. Bu, hem "sessiz" bağlantıların router/NAT tarafından
// arka planda düşürülmesini engelliyor hem de kopan istemcilerin
// hemen fark edilip yeniden bağlanma sürecinin tetiklenmesini sağlıyor.
const heartbeatInterval = setInterval(() => {
    wss.clients.forEach((ws) => {
        if (ws.isAlive === false) {
            ws.terminate();
            return;
        }
        ws.isAlive = false;
        ws.ping();
    });
}, 30000);

wss.on('close', () => clearInterval(heartbeatInterval));

async function main() {
    await initSchema();
    httpServer.listen(PORT, () => {
        console.log(`Magma server listening on port ${PORT}`);
        const addrs = [];
        for (const ifaces of Object.values(os.networkInterfaces())) {
            for (const iface of ifaces || []) {
                if (iface.family === 'IPv4' && !iface.internal) addrs.push(iface.address);
            }
        }
        console.log('LAN addresses friends on the same network can use:');
        for (const a of addrs) console.log(`  http://${a}:${PORT}  (arayüz)`);
        for (const a of addrs) console.log(`  ws://${a}:${PORT}    (websocket)`);
    });
}

main().catch((err) => {
    console.error('Sunucu başlatılamadı:', err);
    process.exit(1);
});