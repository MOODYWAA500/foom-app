require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 3, idleTimeoutMillis: 10000 });
const app = express();
app.set('trust proxy', 1); // behind Vercel's proxy: real client IP for rate limiting
app.use(express.json({ limit: '600kb' }));
app.use(express.static('public'));

// Serverless-friendly: create the tables once per instance, on the first API request.
let ready = null;
app.use('/api', (_req, _res, next) => {
  ready = ready || init().catch(e => { ready = null; throw e; });
  ready.then(() => next(), next);
});
const h = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// ---------- pricing / constants ----------
const PACKAGES = {
  express: { name: 'غسيل إكسبريس سريع', price: 69 },
  vip: { name: 'باقة VIP بلس الشاملة', price: 149 },
  polish: { name: 'تلميع ساطع ديتيلينج', price: 249 },
};
const CAR_EXTRA = { sedan: 0, suv: 25, large: 45 };
const CAR_LABEL = { sedan: 'سيدان', suv: 'SUV / جيب', large: 'كبيرة / جمس' };
const ADDONS = { Wax: ['طبقة واكس نانو', 29], Engine: ['غسيل المحرك', 35], Ozone: ['تعقيم أوزون', 19], Steam: ['بخار للمقاعد', 49] };
const COUPONS = { FOAM20: 0.2 };
const STATUS_LABEL = {
  pending: 'قيد الانتظار', assigned: 'تم تعيين سائق', on_the_way: 'السائق في الطريق',
  arrived: 'وصل السائق', in_progress: 'جاري الغسيل', completed: 'مكتمل', cancelled: 'ملغى',
};
const PAY_STATUS = ['unpaid', 'paid', 'refunded'];
const fmt = n => `${Number(n).toFixed(2)} ر.س`;
const clean = (v, n = 300) => String(v ?? '').trim().slice(0, n);
const digits = v => String(v ?? '').replace(/\D/g, '');

// ---------- auth ----------
const sha = s => crypto.createHash('sha256').update(String(s)).digest();
const fails = new Map();
function requireAdmin(req, res, next) {
  const pass = process.env.ADMIN_PASSWORD;
  if (!pass) return res.status(503).json({ error: 'ADMIN_PASSWORD غير مضبوط في ملف .env' });
  const f = fails.get(req.ip);
  const blocked = f && f.n >= 10 && Date.now() - f.t < 600000;
  if (blocked) return res.status(429).json({ error: 'محاولات كثيرة، حاول بعد 10 دقائق' });
  const m = /^Basic (.+)$/.exec(req.get('authorization') || '');
  let given = '';
  if (m) { const d = Buffer.from(m[1], 'base64').toString(); given = d.slice(d.indexOf(':') + 1); }
  if (m && crypto.timingSafeEqual(sha(given), sha(pass))) { fails.delete(req.ip); return next(); }
  fails.set(req.ip, { n: (f && Date.now() - f.t < 600000 ? f.n : 0) + 1, t: Date.now() });
  res.status(401).json({ error: 'unauthorized' });
}
const hashPw = pw => { const s = crypto.randomBytes(16).toString('hex'); return s + ':' + crypto.scryptSync(pw, s, 64).toString('hex'); };
const checkPw = (pw, stored) => {
  const [s, hx] = String(stored || '').split(':'); if (!s || !hx) return false;
  const a = Buffer.from(hx, 'hex'), b = crypto.scryptSync(pw, s, 64);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};
const requireStaff = h(async (req, res, next) => {
  const t = (/^Bearer (.+)$/.exec(req.get('authorization') || '') || [])[1];
  if (!t) return res.status(401).json({ error: 'unauthorized' });
  const { rows } = await pool.query('SELECT id, full_name FROM staff WHERE token=$1', [t]);
  if (!rows[0]) return res.status(401).json({ error: 'unauthorized' });
  req.staff = rows[0]; next();
});

// ---------- database ----------
async function init() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS staff (
      id SERIAL PRIMARY KEY, role TEXT NOT NULL DEFAULT 'driver', full_name TEXT NOT NULL,
      phone TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, token TEXT, photo_url TEXT,
      created_at TIMESTAMPTZ DEFAULT now());
    ALTER TABLE staff ALTER COLUMN role SET DEFAULT 'driver';
    UPDATE staff SET role='driver' WHERE role='captain';
    CREATE TABLE IF NOT EXISTS customers (
      id SERIAL PRIMARY KEY, name TEXT NOT NULL, phone TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT now());
    CREATE TABLE IF NOT EXISTS customer_sessions (
      token TEXT PRIMARY KEY, customer_id INT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT now());
    CREATE TABLE IF NOT EXISTS orders (
      id TEXT PRIMARY KEY, client_id TEXT NOT NULL,
      package_key TEXT NOT NULL, package_title TEXT NOT NULL, car_type TEXT NOT NULL,
      addons TEXT[] DEFAULT '{}', time_slot TEXT, pay_method TEXT,
      city TEXT, district TEXT, street TEXT, notes TEXT, coupon TEXT,
      subtotal NUMERIC(10,2), discount NUMERIC(10,2), vat NUMERIC(10,2), total NUMERIC(10,2),
      otp_code TEXT, status TEXT DEFAULT 'pending', created_at TIMESTAMPTZ DEFAULT now());
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS customer_id INT REFERENCES customers(id) ON DELETE SET NULL;
    CREATE INDEX IF NOT EXISTS orders_customer_idx ON orders(customer_id, created_at DESC);
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS customer_name TEXT;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS customer_phone TEXT;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS lat DOUBLE PRECISION;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS lng DOUBLE PRECISION;
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_status TEXT DEFAULT 'unpaid';
    ALTER TABLE orders ADD COLUMN IF NOT EXISTS captain_id INT REFERENCES staff(id) ON DELETE SET NULL;
    ALTER TABLE orders ALTER COLUMN status SET DEFAULT 'pending';
    UPDATE orders SET status='pending' WHERE status='جاري التوصيل';
    CREATE INDEX IF NOT EXISTS orders_client_idx ON orders(client_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS orders_captain_idx ON orders(captain_id);
    CREATE TABLE IF NOT EXISTS tracking (staff_id INT PRIMARY KEY REFERENCES staff(id) ON DELETE CASCADE,
      lat DOUBLE PRECISION, lng DOUBLE PRECISION, updated_at TIMESTAMPTZ DEFAULT now());
    CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value JSONB NOT NULL);
    CREATE TABLE IF NOT EXISTS products (id SERIAL PRIMARY KEY, name TEXT NOT NULL, price NUMERIC(10,2) NOT NULL, img TEXT);`);
  const { rows } = await pool.query('SELECT count(*)::int c FROM products');
  if (!rows[0].c) {
    for (const [n, p, t] of [['منشفة ميكروفايبر فاخرة 600GSM', 19, 'Microfiber'], ['معطر فوم الإيطالي برائحة العود', 15, 'Air+Freshener'],
      ['سائل غسيل رغوي شامبو 1 ليتر', 39, 'Foam+Shampoo'], ['بخاخ ملمع الإطارات الأسود', 25, 'Tire+Shine']])
      await pool.query('INSERT INTO products(name,price,img) VALUES($1,$2,$3)', [n, p, `https://placehold.co/180x140/F3F5FC/1642f6?text=${t}`]);
  }
}

// ---------- shapes ----------
const publicShape = o => ({
  id: o.id, packageTitle: o.package_title, carType: (CAR_LABEL[o.car_type] || o.car_type),
  totalAmount: fmt(o.total), status: o.status, statusLabel: STATUS_LABEL[o.status] || o.status,
  otpCode: o.otp_code, address: `${o.city}، ${o.district}`, date: o.created_at,
});
const adminShape = o => ({
  id: o.id, customer_id: o.customer_id, client_name: o.customer_name, client_phone: o.customer_phone,
  package_title: o.package_title, car_type: o.car_type, car_label: CAR_LABEL[o.car_type] || o.car_type,
  addons: (o.addons || []).map(a => (ADDONS[a] ? ADDONS[a][0] : a)),
  subtotal: Number(o.subtotal), discount: Number(o.discount), vat: Number(o.vat), total: Number(o.total),
  coupon: o.coupon, time_slot: o.time_slot, pay_method: o.pay_method,
  city: o.city, district: o.district, street: o.street, notes: o.notes, lat: o.lat, lng: o.lng,
  status: o.status, payment_status: o.payment_status, captain_id: o.captain_id,
  captain_name: o.captain_name || null, created_at: o.created_at,
});

// ---------- public API ----------
const clientId = req => String(req.get('x-client-id') || '').slice(0, 64);

// ---------- customer accounts ----------
const optCustomer = h(async (req, _res, next) => {
  req.customer = null;
  const t = (/^Bearer (.+)$/.exec(req.get('authorization') || '') || [])[1];
  if (t) {
    const { rows } = await pool.query(
      'SELECT c.id, c.name, c.phone FROM customer_sessions s JOIN customers c ON c.id=s.customer_id WHERE s.token=$1', [t]);
    req.customer = rows[0] || null;
    req.customerToken = t;
  }
  next();
});
const requireCustomer = [optCustomer, (req, res, next) => (req.customer ? next() : res.status(401).json({ error: 'unauthorized' }))];
const loginFails = new Map();
const limited = k => { const f = loginFails.get(k); return f && f.n >= 8 && Date.now() - f.t < 600000; };
const noteFail = k => { const f = loginFails.get(k); loginFails.set(k, { n: (f && Date.now() - f.t < 600000 ? f.n : 0) + 1, t: Date.now() }); };
async function newSession(customerId) {
  const token = crypto.randomBytes(32).toString('hex');
  await pool.query('INSERT INTO customer_sessions(token, customer_id) VALUES($1,$2)', [token, customerId]);
  return token;
}
// Only guest orders made from THIS device with the SAME phone are attached to the account.
async function linkGuestOrders(customerId, cid, phone) {
  if (cid) await pool.query('UPDATE orders SET customer_id=$1 WHERE client_id=$2 AND customer_phone=$3 AND customer_id IS NULL', [customerId, cid, phone]);
}

app.post('/api/customer/register', h(async (req, res) => {
  const b = req.body || {}, name = clean(b.name, 60), phone = digits(b.phone), pw = String(b.password || '');
  if (name.length < 2 || phone.length < 9 || phone.length > 15) return res.status(400).json({ error: 'الاسم أو رقم الجوال غير صحيح' });
  if (pw.length < 6 || pw.length > 100) return res.status(400).json({ error: 'الرقم السري 6 خانات على الأقل' });
  let row;
  try {
    row = (await pool.query('INSERT INTO customers(name,phone,password_hash) VALUES($1,$2,$3) RETURNING id,name,phone', [name, phone, hashPw(pw)])).rows[0];
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'هذا الرقم لديه حساب، سجّل دخولك' });
    throw e;
  }
  await linkGuestOrders(row.id, clientId(req), phone);
  res.status(201).json({ token: await newSession(row.id), name: row.name, phone: row.phone });
}));

app.post('/api/customer/login', h(async (req, res) => {
  const phone = digits((req.body || {}).phone), pw = String((req.body || {}).password || ''), key = req.ip + ':' + phone;
  if (limited(key)) return res.status(429).json({ error: 'محاولات كثيرة، حاول بعد 10 دقائق' });
  const { rows } = await pool.query('SELECT * FROM customers WHERE phone=$1', [phone]);
  if (!rows[0] || !checkPw(pw, rows[0].password_hash)) { noteFail(key); return res.status(401).json({ error: 'الجوال أو الرقم السري غير صحيح' }); }
  loginFails.delete(key);
  await linkGuestOrders(rows[0].id, clientId(req), phone);
  res.json({ token: await newSession(rows[0].id), name: rows[0].name, phone: rows[0].phone });
}));

app.get('/api/customer/me', requireCustomer, (req, res) => res.json({ name: req.customer.name, phone: req.customer.phone }));
app.post('/api/customer/logout', requireCustomer, h(async (req, res) => {
  await pool.query('DELETE FROM customer_sessions WHERE token=$1', [req.customerToken]);
  res.json({ ok: true });
}));

app.get('/api/products', h(async (_q, res) => {
  const { rows } = await pool.query('SELECT id,name,price::float,img FROM products ORDER BY id');
  res.json(rows);
}));

app.get('/api/orders', optCustomer, h(async (req, res) => {
  if (req.customer) {
    const { rows } = await pool.query('SELECT * FROM orders WHERE customer_id=$1 ORDER BY created_at DESC LIMIT 100', [req.customer.id]);
    return res.json(rows.map(publicShape));
  }
  const cid = clientId(req);
  if (!cid) return res.json([]);
  const { rows } = await pool.query('SELECT * FROM orders WHERE client_id=$1 AND customer_id IS NULL ORDER BY created_at DESC LIMIT 50', [cid]);
  res.json(rows.map(publicShape));
}));

// Prices are always calculated on the server.
app.post('/api/orders', optCustomer, h(async (req, res) => {
  const cid = clientId(req), b = req.body || {};
  const pkg = PACKAGES[b.packageKey];
  const name = req.customer ? req.customer.name : clean(b.customerName, 60), phone = req.customer ? req.customer.phone : digits(b.customerPhone);
  if (!cid || !pkg || !(b.carType in CAR_EXTRA)) return res.status(400).json({ error: 'بيانات غير صالحة' });
  if (name.length < 2 || phone.length < 9 || phone.length > 15) return res.status(400).json({ error: 'الاسم أو رقم الجوال غير صحيح' });
  const addons = (Array.isArray(b.addons) ? b.addons : []).filter(a => a in ADDONS);
  const subtotal = pkg.price + CAR_EXTRA[b.carType] + addons.reduce((s, a) => s + ADDONS[a][1], 0);
  const rate = COUPONS[String(b.coupon || '').toUpperCase()] || 0;
  const discount = subtotal * rate, vat = (subtotal - discount) * 0.15, total = subtotal - discount + vat;
  const id = '#FOAM-' + Math.floor(10000 + Math.random() * 90000);
  const otp = String(Math.floor(1000 + Math.random() * 9000));
  const lat = Number(b.lat), lng = Number(b.lng);
  const okGeo = Number.isFinite(lat) && Number.isFinite(lng) && Math.abs(lat) <= 90 && Math.abs(lng) <= 180 && (lat || lng);
  const { rows } = await pool.query(
    `INSERT INTO orders(id,client_id,package_key,package_title,car_type,addons,time_slot,pay_method,city,district,street,notes,coupon,
      subtotal,discount,vat,total,otp_code,customer_name,customer_phone,lat,lng,customer_id)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23) RETURNING *`,
    [id, cid, b.packageKey, pkg.name, b.carType, addons, clean(b.timeSlot, 20), clean(b.payMethod, 20), clean(b.city, 50), clean(b.district, 50),
     clean(b.street), clean(b.notes), rate ? String(b.coupon).toUpperCase() : null, subtotal, discount, vat, total, otp,
     name, phone, okGeo ? lat : null, okGeo ? lng : null, req.customer ? req.customer.id : null]);
  res.status(201).json(publicShape(rows[0]));
}));

// ---------- admin API ----------
const A = express.Router();
A.use(requireAdmin);

A.get('/bookings', h(async (_q, res) => {
  const { rows } = await pool.query(
    `SELECT o.*, s.full_name captain_name FROM orders o LEFT JOIN staff s ON s.id=o.captain_id ORDER BY o.created_at DESC LIMIT 500`);
  res.json(rows.map(adminShape));
}));

A.put('/bookings/:id', h(async (req, res) => {
  const b = req.body || {};
  if (!(b.status in STATUS_LABEL) || !PAY_STATUS.includes(b.payment_status)) return res.status(400).json({ error: 'قيمة غير صالحة' });
  let captain = b.captain_id ? parseInt(b.captain_id, 10) : null;
  let status = b.status;
  if (captain) {
    const ok = await pool.query('SELECT 1 FROM staff WHERE id=$1', [captain]);
    if (!ok.rowCount) return res.status(400).json({ error: 'السائق غير موجود' });
    if (status === 'pending') status = 'assigned';
  }
  const r = await pool.query('UPDATE orders SET status=$1, captain_id=$2, payment_status=$3 WHERE id=$4 RETURNING id',
    [status, captain, b.payment_status, req.params.id]);
  if (!r.rowCount) return res.status(404).json({ error: 'الطلب غير موجود' });
  res.json({ ok: true });
}));

A.get('/staff', h(async (_q, res) => {
  const { rows } = await pool.query('SELECT id, role, full_name, phone, photo_url, created_at FROM staff ORDER BY id');
  res.json(rows);
}));

A.post('/staff', h(async (req, res) => {
  const b = req.body || {};
  const name = clean(b.full_name, 60), phone = digits(b.phone), pw = String(b.password || '');
  if (name.length < 2 || phone.length < 9 || phone.length > 15) return res.status(400).json({ error: 'الاسم أو رقم الجوال غير صحيح' });
  if (pw.length < 8) return res.status(400).json({ error: 'كلمة المرور 8 أحرف على الأقل' });
  const photo = typeof b.photo === 'string' && b.photo.startsWith('data:image/') && b.photo.length < 450000 ? b.photo : null;
  try {
    await pool.query('INSERT INTO staff(full_name,phone,password_hash,photo_url) VALUES($1,$2,$3,$4)', [name, phone, hashPw(pw), photo]);
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'رقم الجوال مسجل مسبقاً' });
    throw e;
  }
  res.status(201).json({ ok: true });
}));

A.delete('/staff/:id', h(async (req, res) => {
  await pool.query('DELETE FROM staff WHERE id=$1', [parseInt(req.params.id, 10)]);
  res.json({ ok: true });
}));

A.put('/staff/:id/password', h(async (req, res) => {
  const pw = String((req.body || {}).password || '');
  if (pw.length < 8) return res.status(400).json({ error: 'كلمة المرور 8 أحرف على الأقل' });
  await pool.query('UPDATE staff SET password_hash=$1, token=NULL WHERE id=$2', [hashPw(pw), parseInt(req.params.id, 10)]);
  res.json({ ok: true });
}));

A.put('/customers/:id/password', h(async (req, res) => {
  const pw = String((req.body || {}).password || ''), id = parseInt(req.params.id, 10);
  if (pw.length < 6) return res.status(400).json({ error: 'الرقم السري 6 خانات على الأقل' });
  await pool.query('UPDATE customers SET password_hash=$1 WHERE id=$2', [hashPw(pw), id]);
  await pool.query('DELETE FROM customer_sessions WHERE customer_id=$1', [id]);
  res.json({ ok: true });
}));

A.get('/tracking', h(async (_q, res) => {
  const { rows } = await pool.query(
    `SELECT s.id user_id, s.full_name captain_name, t.lat, t.lng,
            EXTRACT(EPOCH FROM (now()-t.updated_at))::int age_seconds
     FROM staff s LEFT JOIN tracking t ON t.staff_id=s.id ORDER BY s.id`);
  res.json(rows);
}));

A.get('/settings', h(async (_q, res) => {
  const { rows } = await pool.query("SELECT value FROM settings WHERE key='bank'");
  res.json(rows[0] ? rows[0].value : {});
}));

A.post('/settings', h(async (req, res) => {
  const b = req.body || {};
  const v = { bank_name: clean(b.bank_name, 80), account_holder: clean(b.account_holder, 80), iban: clean(b.iban, 40), note: clean(b.note, 200) };
  await pool.query("INSERT INTO settings(key,value) VALUES('bank',$1) ON CONFLICT (key) DO UPDATE SET value=$1", [v]);
  res.json({ ok: true });
}));
app.use('/api/admin', A);

// ---------- captain API ----------
app.post('/api/staff/login', h(async (req, res) => {
  const phone = digits((req.body || {}).phone), pw = String((req.body || {}).password || '');
  const { rows } = await pool.query('SELECT * FROM staff WHERE phone=$1', [phone]);
  if (!rows[0] || !checkPw(pw, rows[0].password_hash)) return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
  const token = crypto.randomBytes(32).toString('hex');
  await pool.query('UPDATE staff SET token=$1 WHERE id=$2', [token, rows[0].id]);
  res.json({ token, name: rows[0].full_name });
}));

app.get('/api/staff/jobs', requireStaff, h(async (req, res) => {
  const { rows } = await pool.query(
    "SELECT * FROM orders WHERE captain_id=$1 AND status NOT IN ('completed','cancelled') ORDER BY created_at", [req.staff.id]);
  res.json(rows.map(adminShape));
}));

app.put('/api/staff/jobs/:id/status', requireStaff, h(async (req, res) => {
  const st = (req.body || {}).status;
  if (!['on_the_way', 'arrived', 'in_progress', 'completed'].includes(st)) return res.status(400).json({ error: 'حالة غير صالحة' });
  const r = await pool.query('UPDATE orders SET status=$1 WHERE id=$2 AND captain_id=$3 RETURNING id', [st, req.params.id, req.staff.id]);
  if (!r.rowCount) return res.status(404).json({ error: 'الطلب غير موجود' });
  res.json({ ok: true });
}));

app.post('/api/staff/location', requireStaff, h(async (req, res) => {
  const lat = Number(req.body.lat), lng = Number(req.body.lng);
  if (!Number.isFinite(lat) || !Number.isFinite(lng) || Math.abs(lat) > 90 || Math.abs(lng) > 180) return res.status(400).json({ error: 'إحداثيات غير صالحة' });
  await pool.query(`INSERT INTO tracking(staff_id,lat,lng,updated_at) VALUES($1,$2,$3,now())
    ON CONFLICT (staff_id) DO UPDATE SET lat=$2, lng=$3, updated_at=now()`, [req.staff.id, lat, lng]);
  res.json({ ok: true });
}));

app.use((err, _req, res, _next) => { console.error(err); res.status(500).json({ error: 'خطأ في الخادم' }); });

// Vercel imports the app; `node server.js` (npm start) runs it locally.
module.exports = app;
module.exports.init = init;
if (require.main === module) {
  ready = init();
  ready.then(() => app.listen(process.env.PORT || 3000, () => console.log('FOAM running on :' + (process.env.PORT || 3000))))
    .catch(e => { console.error('DB init failed:', e.message); process.exit(1); });
}
