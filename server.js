// server.js — versión final (login solo usuario, auto lluvia y mensual WU)

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
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT,
    session_id TEXT
  )
`).run();

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
    const apiKey   = process.env.WU_API_KEY;
    const stationId = req.query.stationId || process.env.WU_STATION_ID;
    const units    = req.query.units || 'm';
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

/* ========== Weather Underground: histórico diario ========== */
/* Acepta YYYYMMDD o YYYY-MM-DD y recorta endDate a HOY si viene futuro */
app.get('/api/weather/history', requiereSesionUnica, async (req, res) => {
  try {
    const apiKey    = process.env.WU_API_KEY;
    const stationId = req.query.stationId || process.env.WU_STATION_ID;
    let { startDate, endDate } = req.query;
    const units     = req.query.units || 'm';

    if (!apiKey || !stationId) return res.status(400).json({ error: 'config_missing' });
    if (!startDate || !endDate) return res.status(400).json({ error: 'params_missing', detalle: 'startDate y endDate son obligatorios' });

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
    const ct = (r.headers.get('content-type') || '').toLowerCase();
    const body = await r.text();

    if (!r.ok) {
      console.error('Upstream /history error', r.status, ct, body.slice(0, 300));
      return res.status(r.status).json({ error: 'weather.com denied', status: r.status });
    }
    if (!ct.includes('application/json')) {
      console.error('Unexpected content-type /history:', ct, body.slice(0, 300));
      return res.status(502).json({ error: 'Invalid response from weather.com' });
    }

    res.set('Cache-Control', 'public, max-age=300');
    res.type('application/json').send(body);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Weather history proxy failed' });
  }
});

/* ========== NUEVO: total de lluvia del MES (suma precipTotal) ========== */
/* Uso: GET /api/lluvia/total/month?ym=2025-10  (o year=2025&month=10) */
app.get('/api/lluvia/total/month', requiereSesionUnica, async (req, res) => {
  try {
    const apiKey    = process.env.WU_API_KEY;
    const stationId = req.query.stationId || process.env.WU_STATION_ID;
    if (!apiKey || !stationId) return res.status(400).json({ error: 'config_missing' });

    const ym = req.query.ym;
    let year = parseInt(req.query.year, 10);
    let month = parseInt(req.query.month, 10);

    if (ym && /^\d{4}-\d{2}$/.test(ym)) {
      year = parseInt(ym.slice(0,4), 10);
      month = parseInt(ym.slice(5,7), 10);
    }
    if (!year || !month || month < 1 || month > 12) {
      return res.status(400).json({ error: 'params_missing', detalle: 'Proporciona ym=YYYY-MM o year y month' });
    }

    const pad = n => String(n).padStart(2, '0');
    const startDate = `${year}${pad(month)}01`;
    const endDate   = `${year}${pad(month)}31`; // WU ignora días inexistentes

    // Llamamos a nuestra propia ruta history (normaliza y recorta a hoy)
    const url = new URL(`${req.protocol}://${req.get('host')}/api/weather/history`);
    url.searchParams.set('stationId', stationId);
    url.searchParams.set('startDate', startDate);
    url.searchParams.set('endDate', endDate);
    url.searchParams.set('units', 'm');

    const r = await fetch(url.href, { headers: { Cookie: req.headers.cookie || '' } });
    if (!r.ok) return res.status(r.status).json({ error: 'history_failed' });
    const data = await r.json();

    const obs = Array.isArray(data?.observations) ? data.observations : [];
    const total = obs.reduce((acc, d) => acc + (+d?.metric?.precipTotal || 0), 0);

    return res.json({
      year, month,
      total_mm: Number(total.toFixed(2)),
      days: obs.length
    });
  } catch (e) {
    console.error('Error /api/lluvia/total/month:', e);
    res.status(500).json({ error: 'calc_failed' });
  }
});

/* ========== AUTO ACTUALIZADOR DE LLUVIA DIARIA (sin duplicados) ========== */
async function actualizarLluviaAutomatica() {
  try {
    const stationId = process.env.WU_STATION_ID || "IALFAR32";
    // Si sirves front y back en el mismo dominio, podrías llamar directamente a WU;
    // uso nuestra proxy actual para unificar manejo de claves.
    const baseUrl = `https://aver-production.up.railway.app/api/weather/current?stationId=${encodeURIComponent(stationId)}`;
    const resp = await fetch(baseUrl);
    const data = await resp.json();

    if (data?.observations?.[0]?.metric?.precipTotal != null) {
      const mm = data.observations[0].metric.precipTotal;
      const fecha = new Date().toISOString().split("T")[0];

      const rainPath = path.join(DB_DIR, 'lluvia.db');
      const rainDB = new Database(rainPath);
      rainDB.pragma('journal_mode=wal');
      rainDB.prepare(`CREATE TABLE IF NOT EXISTS lluvia (fecha TEXT PRIMARY KEY, mm REAL)`).run();
      const row = rainDB.prepare("SELECT * FROM lluvia WHERE fecha=?").get(fecha);
      if (row) {
        rainDB.prepare("UPDATE lluvia SET mm=? WHERE fecha=?").run(mm, fecha);
        console.log(`💧 Lluvia actualizada automáticamente: ${mm} mm (${fecha})`);
      } else {
        rainDB.prepare("INSERT INTO lluvia (fecha,mm) VALUES (?,?)").run(fecha, mm);
        console.log(`💧 Lluvia registrada automáticamente: ${mm} mm (${fecha})`);
      }
      rainDB.close();
    }
  } catch (err) {
    console.error("⚠️ Error al actualizar lluvia automática:", err);
  }
}
setInterval(actualizarLluviaAutomatica, 6 * 60 * 60 * 1000);
actualizarLluviaAutomatica();

/* ===================== Arranque ===================== */
const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Servidor activo en puerto ${PORT}`));

