/**
 * server.js — listo para Railway:
 * - Healthcheck: /salud (y alias /health)
 * - Sesiones en SQLite (persistentes)
 * - Usuarios en SQLite (persistentes)
 * - Protección de /inicio y /historial
 */

const path = require("path");
const fs = require("fs");
const express = require("express");
const cors = require("cors");
const session = require("express-session");
const SQLiteStoreFactory = require("connect-sqlite3");
const SQLiteStore = SQLiteStoreFactory(session);
const Database = require("better-sqlite3");

// -------------------- Config --------------------
const app = express();
const NODE_ENV = process.env.NODE_ENV || "development";
const IS_PROD = NODE_ENV === "production";
const PORT = process.env.PORT || 3000;
const HOST = "0.0.0.0";

// Detrás de proxy (Railway) para cookies secure
app.set("trust proxy", 1);

// Directorios
const p = (...segs) => path.join(__dirname, ...segs);
const PUBLIC_DIR = p("public");

// Persistencia: usa volumen /data si existe
const DATA_DIR = process.env.DATA_DIR || p("db");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// -------------------- Middlewares --------------------
app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// Sesiones persistentes en SQLite
app.use(
  session({
    store: new SQLiteStore({ dir: DATA_DIR, db: "sessions.sqlite" }),
    name: "sid",
    secret: process.env.SESSION_SECRET || "dev-only-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: IS_PROD, // true en prod detrás de TLS
      maxAge: 1000 * 60 * 60 * 8, // 8h
    },
  })
);

// -------------------- DB Usuarios --------------------
const USERS_DB_FILE = path.join(DATA_DIR, "usuarios.db");
const db = new Database(USERS_DB_FILE);

// Esquema mínimo (compatible con tus scripts)
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY,
  password TEXT NOT NULL,
  session_id TEXT
);
`);

const stmtGetUser = db.prepare("SELECT username, password FROM users WHERE username = ?");
const stmtInsertUser = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)");

// Crea admin por defecto si no existe (una sola vez)
try {
  stmtInsertUser.run("admin", "admin");
  console.log("Usuario admin creado por defecto");
} catch (_) {
  /* ya existía */
}

// -------------------- Healthcheck --------------------
app.get("/salud", (_req, res) => res.status(200).send("ok"));
app.get("/health", (_req, res) => res.status(200).send("ok")); // alias por si tu proyecto lo usa

// -------------------- Auth --------------------
async function validateUser(username, password) {
  const row = stmtGetUser.get(username);
  if (row && row.password === password) return { id: username, username };
  return null;
}

function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.redirect("/login.html");
}

// Bloqueo de acceso directo a HTML protegidos
const PROTECTED_HTML = new Set(["/inicio.html", "/historial.html"]);
app.use((req, res, next) => {
  if (PROTECTED_HTML.has(req.path) && (!req.session || !req.session.user)) {
    return res.redirect("/login.html");
  }
  next();
});

// Rutas auth
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ ok: false, error: "Faltan credenciales" });

    const user = await validateUser(username, password);
    if (!user) return res.status(401).json({ ok: false, error: "Credenciales inválidas" });

    req.session.user = { id: user.id, username: user.username };
    return res.json({ ok: true, user: req.session.user });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ ok: false, error: "Error interno" });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("sid");
    return res.json({ ok: true });
  });
});

app.get("/api/me", (req, res) => {
  if (!req.session || !req.session.user) return res.status(401).json({ ok: false });
  return res.json({ ok: true, user: req.session.user });
});

// (Opcional) Endpoint admin para crear usuarios desde fuera (proteger con token)
app.post("/api/admin/crear-usuario", (req, res) => {
  if (!process.env.ADMIN_TOKEN || req.headers["x-admin-token"] !== process.env.ADMIN_TOKEN) {
    return res.status(403).json({ ok: false, error: "Forbidden" });
  }
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ ok: false, error: "Datos incompletos" });
  try {
    stmtInsertUser.run(username, password);
    return res.json({ ok: true });
  } catch (e) {
    if (String(e).includes("UNIQUE")) return res.status(409).json({ ok: false, error: "Usuario ya existe" });
    console.error(e);
    return res.status(500).json({ ok: false, error: "Error creando usuario" });
  }
});

// -------------------- Páginas y estáticos --------------------
app.get("/", (_req, res) => res.sendFile(path.join(PUBLIC_DIR, "login.html")));
app.get("/login", (_req, res) => res.redirect("/login.html"));
app.get("/inicio", requireAuth, (_req, res) => res.sendFile(path.join(PUBLIC_DIR, "inicio.html")));
app.get("/historial", requireAuth, (_req, res) => res.sendFile(path.join(PUBLIC_DIR, "historial.html")));

app.use(
  express.static(PUBLIC_DIR, {
    extensions: ["html"],
    setHeaders(res, filePath) {
      if (filePath.endsWith(".html")) res.setHeader("Cache-Control", "no-store");
    },
  })
);

// 404
app.use((_, res) => res.status(404).send("<h1>404</h1><p>Recurso no encontrado.</p>"));

// -------------------- Arranque --------------------
app.listen(PORT, HOST, () => {
  console.log(`Servidor en http://${HOST}:${PORT} (env:${NODE_ENV})`);
  console.log("DB usuarios:", USERS_DB_FILE);
});
