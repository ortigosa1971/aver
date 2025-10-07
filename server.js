// server.js — versión final con login simplificado y auto actualización de lluvia

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

// ====== CORS ======
const ALLOWED = (process.env.CORS_ORIGINS || process.env.CORS_ORIGIN || '')
  .split(',')
  .map(s => s.trim().replace(/\/+$/, ''))
  .filter(Boolean);

const corsMiddleware = cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    if (ALLOWED.length === 0) return cb(null, true);
    const clean = origin.replace(/\/+$/, '');
    const ok = ALLOWED.includes(clean);
    cb(ok ? null : new Error('Not allowed by CORS'), ok);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 204
});
app.use(corsMiddleware);
app.options('*', corsMiddleware);
app.use((req, res, next) => { res.header('Vary', 'Origin'); next(); });

// ====== Carpetas ======
const DB_DIR = path.join(__dirname, 'db');
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
const PUBLIC_DIR = path.join(__dirname, 'public');
if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR, { recursive: true });

// ====== Sesiones (SQLite) ======
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

// ====== Body & estáticos ======
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(PUBLIC_DIR));

// ====== DB usuarios ======
const db = new Database(path.join(DB_DIR, 'usuarios.db'));
db.pragma('journal_mode=wal');
db.prepare(`CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, session_id TEXT)`).run();

// ====== Healthcheck ======
app.get(['/health', '/salud'], (req, res) => res.status(200).send('OK'));

// ====== Página raíz ======
app.get('/', (req, res) => {
  const f = path.join(PUBLIC_DIR, 'login.html');
  if (fs.existsSync(f)) return res.sendFile(f);
  res.send('<h1>Login</h1>');
});

// ====== LOGIN SIMPLIFICADO (solo usuario, sin contraseña) ======
app.post('/login', async (req, res) => {
  try {
    const user = req.body.usuario?.trim();
    if (!user) return res.redirect('/login.html?error=falta_usuario');

    // Buscar el usuario o crearlo si no existe
    let found = db.prepare('SELECT * FROM users WHERE username = ?').get(user);
    if (!found) {
      db.prepare('INSERT INTO users (username, password, session_id) VALUES (?, NULL, NULL)').run(user);
      found = { username: user };
      console.log(`👤 Usuario creado automáticamente: ${user}`);
    }

    // Cerrar sesión previa si existía
    if (found.session_id) {
      await storeDestroy(found.session_id).catch(() => {});
      db.prepare('UPDATE users SET session_id = NULL WHERE username = ?').run(user);
    }

    // Crear nueva sesión
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

// ====== Sesión única ======
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

// ====== Páginas protegidas ======
app.get('/inicio', requiereSesionUnica, async (req, res) => {
  await actualizarLluviaAutomatica().catch(err => console.error("Auto lluvia:", err));
  const f = path.join(PUBLIC_DIR, 'inicio.html');
  if (fs.existsSync(f)) return res.sendFile(f);
  res.send(`<h1>Inicio</h1><p>Usuario: ${req.session.usuario}</p>`);
});

// ====== Logout ======
app.post('/logout', (req, res) => {
  const u = req.session?.usuario, sid = req.sessionID;
  req.session.destroy(() => {
    if (u) db.prepare('UPDATE users SET session_id=NULL WHERE username=?').run(u);
    res.redirect('/login.html?msg=logout');
  });
});

// ====== API de lluvia (Weather Underground) ======
app.get('/api/weather/current', requiereSesionUnica, async (req, res) => {
  try {
    const apiKey = process.env.WU_API_KEY, stationId = req.query.stationId || process.env.WU_STATION_ID;
    if (!apiKey || !stationId) return res.status(400).json({ error: 'config_missing' });
    const url = `https://api.weather.com/v2/pws/observations/current?stationId=${stationId}&format=json&units=m&apiKey=${apiKey}`;
    const r = await fetch(url); const body = await r.text();
    if (!r.ok) return res.status(r.status).json({ error: 'weather.com denied' });
    res.type('application/json').send(body);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Weather proxy failed' });
  }
});

// ====== AUTO ACTUALIZADOR DE LLUVIA ======
async function actualizarLluviaAutomatica() {
  try {
    const stationId = process.env.WU_STATION_ID || "IALFAR32";
    const baseUrl = `https://aver-production.up.railway.app/api/weather/current?stationId=${stationId}`;
    const resp = await fetch(baseUrl);
    const data = await resp.json();

    if (data?.observations?.[0]?.metric?.precipTotal != null) {
      const mm = data.observations[0].metric.precipTotal;
      const fecha = new Date().toISOString().split("T")[0];

      const check = path.join(DB_DIR, 'lluvia.db');
      const rainDB = new Database(check);
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

// ====== Arranque ======
const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Servidor activo en puerto ${PORT}`));

