const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = 3000;
const DB_FILE = path.join(__dirname, 'db.json');

// Yönetici şifresi
const ADMIN_PASSWORD = 'f06a09e74070e8ddc3791447e10750f5345971fe47a551280b58331bd872de81'; 
const BASE_API = 'https://baseinfo.freesrv.com/?uid=';

app.use(express.json());
app.use(express.static(__dirname));

// Veritabanı İşlemleri
function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const initial = { keys: [], blockedIPs: [] };
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2));
    return initial;
  }
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// IP Adresi Alma
function getClientIP(req) {
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '')
    .split(',')[0].trim().replace('::ffff:', '');
}

// Admin Yetki Kontrolü
function adminAuth(req, res, next) {
  if (req.headers['x-admin-pass'] !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Yetkisiz' });
  }
  next();
}

// Key Doğrulama
function verifyKey(db, key, ip) {
  if (db.blockedIPs.includes(ip)) return { error: 'IP adresiniz engellenmiş.', code: 403 };
  if (!key) return { error: 'Key gerekli.', code: 401 };
  const k = db.keys.find(x => x.key === key);
  if (!k) return { error: 'Geçersiz key.', code: 401 };
  if (k.revoked) return { error: 'Key iptal edilmiş.', code: 403 };
  if (Date.now() > k.expiresAt) return { error: 'Key süresi dolmuş.', code: 403 };
  return { keyObj: k };
}

// ================= PUBLIC API =================

// Key Doğrulama (Giriş için)
app.post('/api/verify-key', (req, res) => {
  const { key } = req.body;
  const ip = getClientIP(req);
  const db = loadDB();
  const v = verifyKey(db, key, ip);
  
  if (v.error) return res.status(v.code).json({ error: v.error });
  
  res.json({
    valid: true,
    label: v.keyObj.label,
    remainingMs: v.keyObj.expiresAt - Date.now()
  });
});

// UID Sorgulama (API Proxy)
app.post('/api/uid-lookup', async (req, res) => {
  const { uid, key } = req.body;
  const ip = getClientIP(req);
  const db = loadDB();
  const v = verifyKey(db, key, ip);
  
  if (v.error) return res.status(v.code).json({ error: v.error });
  if (!uid || !/^\d+$/.test(String(uid))) return res.status(400).json({ error: 'Geçerli bir UID girin.' });

  try {
    const apiRes = await fetch(BASE_API + encodeURIComponent(uid));
    const data = await apiRes.json();

    v.keyObj.uses = (v.keyObj.uses || 0) + 1;
    v.keyObj.lastUsed = Date.now();
    saveDB(db);

    res.json({
      success: true,
      uid,
      data,
      remainingMs: v.keyObj.expiresAt - Date.now()
    });
  } catch (e) {
    res.status(502).json({ error: 'Dış API\'ye ulaşılamadı.' });
  }
});

// ================= ADMIN API =================

// Key Listesi
app.get('/api/admin/keys', adminAuth, (req, res) => res.json(loadDB().keys));

// Key Oluşturma
app.post('/api/admin/keys', adminAuth, (req, res) => {
  const { durationHours, label } = req.body;
  if (!durationHours || durationHours <= 0) return res.status(400).json({ error: 'Geçerli süre girin.' });
  
  const db = loadDB();
  const newKey = {
    key: 'NXN-' + crypto.randomBytes(12).toString('hex').toUpperCase(),
    label: label || 'İsimsiz',
    createdAt: Date.now(),
    expiresAt: Date.now() + durationHours * 3600 * 1000,
    durationHours, 
    revoked: false, 
    uses: 0, 
    lastUsed: null
  };
  
  db.keys.push(newKey);
  saveDB(db);
  res.json(newKey);
});

// Key İptal Etme
app.post('/api/admin/keys/revoke', adminAuth, (req, res) => {
  const db = loadDB();
  const k = db.keys.find(x => x.key === req.body.key);
  if (!k) return res.status(404).json({ error: 'Bulunamadı.' });
  
  k.revoked = true;
  saveDB(db);
  res.json({ success: true });
});

// Key Silme
app.delete('/api/admin/keys/:key', adminAuth, (req, res) => {
  const db = loadDB();
  db.keys = db.keys.filter(k => k.key !== req.params.key);
  saveDB(db);
  res.json({ success: true });
});

// IP Listesi
app.get('/api/admin/ips', adminAuth, (req, res) => res.json(loadDB().blockedIPs));

// IP Engelleme
app.post('/api/admin/ips', adminAuth, (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP gerekli.' });
  
  const db = loadDB();
  if (!db.blockedIPs.includes(ip)) db.blockedIPs.push(ip);
  saveDB(db);
  res.json(db.blockedIPs);
});

// IP Engel Kaldırma
app.delete('/api/admin/ips/:ip', adminAuth, (req, res) => {
  const db = loadDB();
  db.blockedIPs = db.blockedIPs.filter(i => i !== req.params.ip);
  saveDB(db);
  res.json(db.blockedIPs);
});

app.listen(PORT, () => {
  console.log(`Sunucu calisiyor: http://localhost:${PORT}`);
  console.log(`Admin Paneli: http://localhost:${PORT}/admin.html`);
});