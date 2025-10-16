
/**
 * server.js — versión con healthcheck /salud para Railway y protección de /inicio.
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
const HOST = "0.0.0.0"; // importante para PaaS

// Detrás de proxy (Railway) para que secure cookies funcionen con TLS del proxy
app.set("trust proxy", 1);

// Helpers
const p = (...segs) => path.join(__dirname, ...segs);
const PUBLIC_DIR = p("public");
const SESSIONS_DIR = process.env.SESSIONS_DIR || p("db");
if (!fs.existsSync(SESSIONS_DIR)) fs.mkdirSync(SESSIONS_DIR, { recursive: true });

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// Sesión
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
      secure: IS_PROD, // true en producción (TLS)
      maxAge: 1000 * 60 * 60 * 8,
    },
  })
);

// Healthcheck para Railway
app.get("/salud", (_req, res) => res.status(200).send("ok"));

// Auth minimal
const validateUser = async (username, password) => {
  if (username === "admin" && password === "admin") return { id: 1, username: "admin" };
  return null;
};

function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.redirect("/login.html");
}

// Bloqueo acceso directo a HTML protegidos
const PROTECTED_HTML = new Set(["/inicio.html", "/historial.html"]);
app.use((req, res, next) => {
  if (PROTECTED_HTML.has(req.path)) {
    if (!req.session || !req.session.user) {
      return res.redirect("/login.html");
    }
  }
  next();
});

// Rutas auth
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

// Páginas
app.get("/", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "login.html")));
app.get("/login", (req, res) => res.redirect("/login.html"));
app.get("/inicio", requireAuth, (req, res) => res.sendFile(path.join(PUBLIC_DIR, "inicio.html")));
app.get("/historial", requireAuth, (req, res) => res.sendFile(path.join(PUBLIC_DIR, "historial.html")));

// Estáticos
app.use(express.static(PUBLIC_DIR, {
  extensions: ["html"],
  setHeaders(res, filePath) {
    if (filePath.endsWith(".html")) {
      res.setHeader("Cache-Control", "no-store");
    }
  },
}));

// 404
app.use((req, res) => {
  res.status(404).send("<h1>404</h1><p>Recurso no encontrado.</p>");
});

app.listen(PORT, HOST, () => {
  console.log(`Servidor en http://${HOST}:${PORT} (env:${NODE_ENV})`);
});


