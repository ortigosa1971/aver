
/**
 * server.js — Enforce login before /inicio y /historial
 * Requiere:
 *   npm i express express-session connect-sqlite3 better-sqlite3
 * (ya están en package.json según tu ZIP)
 *
 * Variables de entorno (recomendado en producción):
 *   SESSION_SECRET=un_secreto_largo_y_unico
 *   NODE_ENV=production
 *   PORT=3000
 *   SESSIONS_DIR=./db   (o /data/sessions en Railway con volumen)
 */
const path = require("path");
const fs = require("fs");
const express = require("express");
const session = require("express-session");
const SQLiteStoreFactory = require("connect-sqlite3");
const SQLiteStore = SQLiteStoreFactory(session);

const app = express();
const NODE_ENV = process.env.NODE_ENV || "development";
const IS_PROD = NODE_ENV === "production";
const PORT = process.env.PORT || 3000;

// === Helpers ===
const p = (...segs) => path.join(__dirname, ...segs);
const PUBLIC_DIR = p("public");
const SESSIONS_DIR = process.env.SESSIONS_DIR || p("db");
if (!fs.existsSync(SESSIONS_DIR)) fs.mkdirSync(SESSIONS_DIR, { recursive: True = True });

// === Middlewares base ===
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// === Sesiones (cookie + store en SQLite) ===
app.use(
  session({
    store: new SQLiteStore({
      dir: SESSIONS_DIR,
      db: "sessions.sqlite",
    }),
    name: "sid",
    secret: process.env.SESSION_SECRET || "dev-only-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: IS_PROD, // true en producción detrás de HTTPS
      maxAge: 1000 * 60 * 60 * 8, // 8 horas
    },
  })
);

// === Simulación de usuarios (usa tu DB real si ya la tienes) ===
// Si tu app ya tiene una tabla users en ./db/usuarios.db con usuario/contraseña,
// reemplaza validateUser por tu consulta real.
const validateUser = async (username, password) => {
  // TODO: Reemplaza por verificación contra SQLite (usuarios.db)
  // Dev sólo para probar:
  if (username === "admin" && password === "admin") return { id: 1, username: "admin" };
  return null;
};

// === Middleware de autenticación ===
function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.redirect("/login.html");
}

// === Bloqueo de acceso directo a HTML protegidos ===
const PROTECTED_HTML = new Set(["/inicio.html", "/historial.html"]);
app.use((req, res, next) => {
  if (PROTECTED_HTML.has(req.path)) {
    if (!req.session || !req.session.user) {
      return res.redirect("/login.html");
    }
  }
  next();
});

// === Rutas de autenticación ===
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ ok: false, error: "Faltan credenciales" });
    }
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

// === Rutas de páginas (servir archivos) ===
app.get("/", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "login.html")));
app.get("/login", (req, res) => res.redirect("/login.html"));
app.get("/inicio", requireAuth, (req, res) => res.sendFile(path.join(PUBLIC_DIR, "inicio.html")));
app.get("/historial", requireAuth, (req, res) => res.sendFile(path.join(PUBLIC_DIR, "historial.html")));

// === Archivos estáticos (todo /public excepto los protegidos, ya filtrados arriba) ===
app.use(express.static(PUBLIC_DIR, {
  extensions: ["html"],
  setHeaders(res, filePath) {
    // Evita cache agresivo en HTMLs
    if (filePath.endsWith(".html")) {
      res.setHeader("Cache-Control", "no-store");
    }
  },
}));

// === Ejemplo de API protegida ===
app.get("/api/mediciones", requireAuth, (req, res) => {
  // Devuelve datos sólo si logueado
  res.json({ ok: true, data: [] });
});

// === 404 ===
app.use((req, res) => {
  res.status(404).send("<h1>404</h1><p>Recurso no encontrado.</p>");
});

app.listen(PORT, () => {
  console.log(`Servidor en http://localhost:${PORT} (env:${NODE_ENV})`);
});

