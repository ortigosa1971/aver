// server.js — versión final (login solo usuario, lluvia mensual/anual, auto-lluvia)

const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
const util = require('util');
const cors = require('cors');
const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));

const app = express();
app.set('trust proxy', 1);

/* ===================== CORS ===================== */
const ALLOWED = (process.env.CORS_ORIGINS || process.env.CORS_ORIGIN || '')
  .split(',')
  .map(s => s.trim().replace(/\/+$/, ''))
  .filter(Boolean);

const corsMiddleware = cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    if (ALLOWED.length === 0) return cb(null, true);
    const clean = origin.replace(/\/+$/, '');
    cb(ALLOWED.includes(clean) ? null : new Error('Not allowed by CORS'), ALLOWED.includes(clean));
  },
  credentials: true,
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
  optionsSuccessStatus: 204
});
app.use(corsMiddleware);
app.options('*', corsMiddleware);
app.use((req, res, next) => { res.header('Vary', 'Origin'); next(); });

/* ===================== Carpetas ===================== */
const DB_DIR = path.join(__dirname, 'db');
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
const PUBLIC_DIR = path.join(__dirname, 'public');
if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR, { recursive: true });

/* ===================== Sesiones ===================== */
const store = new SQLiteStore({ db: 'sessions.sqlite', dir: DB_DIR });
app.use(session({
  store,
  secret: process.env.SESSION_SECRET || 'clave-secreta',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: process.env.SAMESITE || 'none',
    secure: process.env.COOKIE_SECURE === 'true' || process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 8
  }
}));
const storeGet = util.promisify(store.get).bind(store);
const storeDestroy = util.promisify(store.destroy).bind(store);

/* ===================== Body & estáticos ===================== */
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(PUBLIC_DIR));

/* ===================== DB usuarios ===================== */
const db = new Database(path.join(DB_DIR, 'usuarios.db'));
db.pragma('journal_mode=wal');
db.prepare(`CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, session_id TEXT)`).run();

/* ===================== Healthcheck & raíz ===================== */
app.get(['/health', '/salud'], (req, res) => res.status(200).send('OK'));
app.get('/', (req, res) => {
  const f = path.join(PUBLIC_DIR, 'login.html');
  if (fs.existsSync(f)) return res.sendFile(f);
  res.send('<h1>Login</h1>');
});

/* ===================== LOGIN (solo usuario) ===================== */
app.post('/login', async (req, res) => {
  try {
    const user = req.body.usuario?.trim();
    if (!user) return res.redirect('/login.html?error=falta_usuario');

    let found = db.prepare('SELECT * FROM users WHERE username = ?').get(user);
    if (!found) {
      db.prepare('INSERT INTO users (username, password, session_id) VALUES (?, NULL, NULL)').run(user);
      found = { username: user };
      console.log(`👤 Usuario creado automáticamente: ${user}`);
    }

    if (found.session_id) {
      await storeDestroy(found.session_id).catch(() => {});
      db.prepare('UPDATE users SET session_id = NULL WHERE username = ?').run(user);
    }

    await new Promise((resolve, reject) => req.session.regenerate(e => e ? reject(e) : resolve()));
    const claim = db.prepare('UPDATE users SET session_id = ? WHERE username = ? AND session_id IS NULL')
      .run(req.sessionID, user);
    if (claim.changes === 0) return res.redirect('/login.html?error=sesion_activa');

    req.session.usuario = user;
    console.log(`✅ Sesión iniciada: ${user} (${req.sessionID})`);
    res.redirect('/inicio');
  } catch (e) {
    console.error(e);
    res.redirect('/login.html?error=interno');
  }
});

/* ===================== Sesión única ===================== */
async function requiereSesionUnica(req, res, next) {
  try {
    if (!req.session?.usuario) return res.redirect('/login.html');
    const row = db.prepare('SELECT session_id FROM users WHERE username=?').get(req.session.usuario);
    if (!row || !row.session_id) return req.session.destroy(() => res.redirect('/login.html'));
    if (row.session_id !== req.sessionID) {
      req.session.destroy(() => res.redirect('/login.html?error=conectado_en_otra_maquina'));
      return;
    }
    const sess = await storeGet(row.session_id);
    if (!sess) {
      db.prepare('UPDATE users SET session_id=NULL WHERE username=?').run(req.session.usuario);
      req.session.destroy(() => res.redirect('/login.html?error=sesion_expirada'));
      return;
    }
    next();
  } catch (e) {
    console.error(e);
    res.redirect('/login.html?error=interno');
  }
}

/* ===================== Inicio (protegido) ===================== */
app.get('/inicio', requiereSesionUnica, async (req, res) => {
  await actualizarLluviaAutomatica().catch(err => console.error("Auto lluvia:", err));
  const f = path.join(PUBLIC_DIR, 'inicio.html');
  if (fs.existsSync(f)) return res.sendFile(f);
  res.send(`<h1>Inicio</h1><p>Usuario: ${req.session.usuario}</p>`);
});

/* ===================== Logout ===================== */
app.post('/logout', (req, res) => {
  const u = req.session?.usuario;
  req.session.destroy(() => {
    if (u) db.prepare('UPDATE users SET session_id=NULL WHERE username=?').run(u);
    res.redirect('/login.html?msg=logout');
  });
});

/* ========== Weather Underground: condiciones actuales ========== */
app.get('/api/weather/current', requiereSesionUnica, async (req, res) => {
  try {
    const apiKey    = process.env.WU_API_KEY;
    const stationId = req.query.stationId || process.env.WU_STATION_ID;
    const units     = req.query.units || 'm';
    if (!apiKey || !stationId) return res.status(400).json({ error: 'config_missing' });

    const url = `https://api.weather.com/v2/pws/observations/current?stationId=${encodeURIComponent(stationId)}&format=json&units=${encodeURIComponent(units)}&apiKey=${encodeURIComponent(apiKey)}`;
    const r = await fetch(url);
    const body = await r.text();
    if (!r.ok) return res.status(r.status).json({ error: 'weather.com denied' });

    res.type('application/json').send(body);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Weather proxy failed' });
  }
});

/* ========== Weather Underground: histórico diario (flex fechas) ========== */
app.get('/api/weather/history', requiereSesionUnica, async (req, res) => {
  try {
    const apiKey    = process.env.WU_API_KEY;
    const stationId = req.query.stationId || process.env.WU_STATION_ID;
    let { startDate, endDate } = req.query;
    const units     = 'm';

    if (!apiKey || !stationId) return res.status(400).json({ error: 'config_missing' });
    if (!startDate || !endDate) return res.status(400).json({ error: 'params_missing' });

    const norm = s => String(s).replace(/-/g, '').slice(0, 8);
    startDate = norm(startDate);
    endDate   = norm(endDate);
    if (!/^\d{8}$/.test(startDate) || !/^\d{8}$/.test(endDate)) {
      return res.status(400).json({ error: 'bad_date_format', detalle: 'Usa YYYYMMDD o YYYY-MM-DD' });
    }

    const today = new Date();
    const pad = n => String(n).padStart(2, '0');
    const todayStr = `${today.getFullYear()}${pad(today.getMonth()+1)}${pad(today.getDate())}`;
    if (endDate > todayStr) endDate = todayStr;

    const url = new URL('https://api.weather.com/v2/pws/history/daily');
    url.searchParams.set('stationId', stationId);
    url.searchParams.set('format', 'json');
    url.searchParams.set('units', units);
    url.searchParams.set('startDate', startDate);
    url.searchParams.set('endDate', endDate);
    url.searchParams.set('apiKey', apiKey);

    const r = await fetch(url, { headers: { 'Accept': 'application/json,text/plain,*/*' } });
    const body = await r.text();
    if (!r.ok) return res.status(r.status).json({ error: 'weather.com denied' });

    res.type('application/json').send(body);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Weather history proxy failed' });
  }
});

/* ========== Lluvia total mensual (suma precipTotal) ========== */
app.get('/api/lluvia/total/month', requiereSesionUnica, async (req, res) => {
  try {
    const apiKey    = process.env.WU_API_KEY;
    const stationId = req.query.stationId || process.env.WU_STATION_ID;
    const ym = req.query.ym;
    if (!apiKey || !stationId || !ym) return res.status(400).json({ error: 'params_missing' });

    const [y, m] = ym.split('-');
    const pad = n => String(n).padStart(2, '0');
    const startDate = `${y}${pad(m)}01`;
    const endDate   = `${y}${pad(m)}31`;

    const url = new URL('https://api.weather.com/v2/pws/history/daily');
    url.searchParams.set('stationId', stationId);
    url.searchParams.set('format', 'json');
    url.searchParams.set('units', 'm');
    url.searchParams.set('startDate', startDate);
    url.searchParams.set('endDate', endDate);
    url.searchParams.set('apiKey', apiKey);

    const r = await fetch(url);
    const data = await r.json();
    const obs = Array.isArray(data?.observations) ? data.observations : [];
    const total = obs.reduce((a, d) => a + (+d?.metric?.precipTotal || 0), 0);

    res.json({ year: +y, month: +m, total_mm: +total.toFixed(2), days: obs.length });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'month_failed' });
  }
});

/* ========== Lluvia total anual (con aliases para el front) ========== */
app.get('/api/lluvia/total/year', requiereSesionUnica, async (req, res) => {
  try {
    const apiKey    = process.env.WU_API_KEY;
    const stationId = req.query.stationId || process.env.WU_STATION_ID;
    if (!apiKey || !stationId) return res.status(400).json({ error: 'config_missing' });

    const now  = new Date();
    const year = now.getFullYear();
    const pad  = n => String(n).padStart(2, '0');
    const startDate = `${year}0101`;
    const endDate   = `${year}${pad(now.getMonth()+1)}${pad(now.getDate())}`;

    const url = new URL('https://api.weather.com/v2/pws/history/daily');
    url.searchParams.set('stationId', stationId);
    url.searchParams.set('format', 'json');
    url.searchParams.set('units', 'm');
    url.searchParams.set('startDate', startDate);
    url.searchParams.set('endDate', endDate);
    url.searchParams.set('apiKey', apiKey);

    const r = await fetch(url);
    if (!r.ok) return res.status(r.status).json({ error: 'weather.com denied', status: r.status });

    const data = await r.json();
    const obs = Array.isArray(data?.observations) ? data.observations : [];
    const sum = obs.reduce((acc, d) => acc + (+d?.metric?.precipTotal || 0), 0);
    const total = Number(sum.toFixed(2));

    res.json({
      total_mm: total,       // nombre “correcto”
      total: total,          // alias
      totalLluvia: total,    // alias clásico usado en otros fronts
      value: total,          // alias extra
      year,
      desde: `${year}-01-01`,
      hasta: `${year}-${pad(now.getMonth()+1)}-${pad(now.getDate())}`,
      days: obs.length
    });
  } catch (e) {
    console.error('Error /api/lluvia/total/year:', e);
    res.status(500).json({ error: 'year_failed' });
  }
});

/* Alias por si el front usaba una ruta vieja */
app.get('/api/lluvia/total', (req, res) => res.redirect(307, '/api/lluvia/total/year'));

/* ========== Auto actualización de lluvia diaria (sin duplicados) ========== */
async function actualizarLluviaAutomatica() {
  try {
    const stationId = process.env.WU_STATION_ID || "IALFAR32";
    const resp = await fetch(`https://aver-production.up.railway.app/api/weather/current?stationId=${encodeURIComponent(stationId)}`);
    const data = await resp.json();

    if (data?.observations?.[0]?.metric?.precipTotal != null) {
      const mm = data.observations[0].metric.precipTotal;
      const fecha = new Date().toISOString().split("T")[0];

      const rainDB = new Database(path.join(DB_DIR, 'lluvia.db'));
      rainDB.pragma('journal_mode=wal');
      rainDB.prepare(`CREATE TABLE IF NOT EXISTS lluvia (fecha TEXT PRIMARY KEY, mm REAL)`).run();
      const row = rainDB.prepare("SELECT * FROM lluvia WHERE fecha=?").get(fecha);
      if (row) rainDB.prepare("UPDATE lluvia SET mm=? WHERE fecha=?").run(mm, fecha);
      else rainDB.prepare("INSERT INTO lluvia (fecha,mm) VALUES (?,?)").run(fecha, mm);
      rainDB.close();
    }
  } catch (e) { console.error("⚠️ Auto lluvia:", e); }
}
setInterval(actualizarLluviaAutomatica, 6 * 60 * 60 * 1000);
actualizarLluviaAutomatica();

/* ===================== Arranque ===================== */
const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Servidor activo en puerto ${PORT}`));

