const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');
const app = express();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

app.use(express.json());

// HWID Şifreleme
function encryptHWID(hwid) {
  return crypto.createHash('sha256').update(hwid + 'TÜRK_KEY_2024').digest('hex');
}

// Lisans Kontrol
app.post('/check', async (req, res) => {
  const { key, hwid } = req.body;
  const encryptedHWID = encryptHWID(hwid);

  try {
    const result = await pool.query(
      'SELECT * FROM licenses WHERE key = $1 AND (hwid IS NULL OR hwid = $2) AND expiry > NOW() AND is_active = TRUE',
      [key, encryptedHWID]
    );

    if (result.rows.length === 0) {
      return res.status(403).json({ error: "Geçersiz lisans!" });
    }

    res.json({ valid: true, expiry: result.rows[0].expiry });
  } catch (err) {
    res.status(500).json({ error: "Sunucu hatası!" });
  }
});

// Yeni Key Ekleme (Admin)
app.post('/admin/add', async (req, res) => {
  const { adminPass, key, expiryDays } = req.body;
  if (adminPass !== "GİZLİ_ADMIN_ŞİFRESİ") {
    return res.status(401).json({ error: "Yetkisiz erişim!" });
  }

  const expiryDate = new Date();
  expiryDate.setDate(expiryDate.getDate() + expiryDays);

  await pool.query(
    'INSERT INTO licenses (key, expiry) VALUES ($1, $2)',
    [key, expiryDate.toISOString()]
  );

  res.json({ success: true, key });
});

app.listen(process.env.PORT || 3000, () => console.log("Çalışıyor!"));