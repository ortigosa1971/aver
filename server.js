// server.js
// Servidor Express con sesiones y login contra SQLite (better-sqlite3)

const path = require("path");
const fs = require("fs");
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");

const app = express();

// ===== Configuración =====
const NODE_ENV = process.env.NODE_ENV || "development";
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "0.0.0.0";
const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  "cambia-ESTO-por-un-secreto-largo-y-unico-en-produccion";

// Rutas/archivos
const ROOT_DIR = __dirname;
const PUBLIC_DIR = path.join(ROOT_DIR, "public");
const DB_DIR = path.join(ROOT_DIR, "db");
const DB_PATH = path.join(DB_DIR, "usuarios.db");

// Asegura carpeta DB
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });

// ===== Utilidad DB =====
function getDB() {
  return new Database(DB_PATH);
}
function ensureUsersTable() {
  const db = getDB();
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);
  db.close();
}
ensureUsersTable();

// ===== Middlewares base =====
app.disable("x-powered-by");

// Body parsers
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Sesiones (SQLite Store)
app.use(
  session({
    store: new SQLiteStore({
      db: "sessions.db",
      dir: DB_DIR,
    }),
    name: "sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: NODE_ENV === "production", // true si sirves por HTTPS
      maxAge: 1000 * 60 * 60 * 8, // 8 horas
    },
  })
);

// Estáticos
app.use(express.static(PUBLIC_DIR));

// ===== Healthcheck =====
app.get("/salud", (_req, res) => {
  res.type("text").send("ok");
});

// ===== Protección de páginas privadas (HTML) =====
const paginasPrivadas = new Set(["/inicio.html", "/historial.html"]);
app.use((req, res, next) => {
  if (paginasPrivadas.has(req.path)) {
    if (!req.session || !req.session.userId) {
      return res.redirect("/login.html?error=unauthorized");
    }
  }
  next();
});

// ===== API de autenticación =====
app.post("/login", (req, res) => {
  try {
    const b = req.body || {};
    // Acepta variantes: username/usuario/user y password/pass/contraseña/contrasena
    const username =
      (b.username ?? b.usuario ?? b.user ?? "").toString().trim();
    const password =
      (b.password ?? b.pass ?? b.contrasena ?? b["contraseña"] ?? "")
        .toString();

    if (!username || !password) {
      return res.status(400).json({ error: "campos_faltantes" });
    }

    const db = getDB();
    const row = db
      .prepare("SELECT id, username, password FROM users WHERE username = ?")
      .get(username);

    if (!row || row.password !== password) {
      db.close();
      return res.status(401).json({ error: "credenciales_invalidas" });
    }

    // Sesión
    req.session.userId = row.id;
    req.session.username = row.username;

    db.close();
    return res.json({ ok: true });
  } catch (err) {
    console.error("login error:", err);
    return res.status(500).json({ error: "error_servidor" });
  }
});

app.post("/logout", (req, res) => {
  try {
    if (req.session) {
      req.session.destroy(() => res.json({ ok: true }));
    } else {
      res.json({ ok: true });
    }
  } catch {
    res.json({ ok: true });
  }
});

app.get("/whoami", (req, res) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ authenticated: false });
  }
  res.json({
    authenticated: true,
    id: req.session.userId,
    username: req.session.username,
  });
});

// ===== 404 genérico (después de todas las rutas) =====
app.use((req, res) => {
  res.status(404).type("text").send("Recurso no encontrado.");
});

// ===== Arranque =====
app.listen(PORT, HOST, () => {
  console.log(`Servidor en http://${HOST}:${PORT} (env:${NODE_ENV})`);
});
