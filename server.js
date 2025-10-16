/**
 * server.js — Railway listo
 * - Healthcheck: /salud (+ /health)
 * - Sesiones en SQLite (connect-sqlite3)
 * - Login tolerante (distintos nombres de campos y Basic Auth)
 * - Busca automáticamente la página de login (con o sin tildes/espacios)
 * - Protege /inicio y /historial
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

app.set("trust proxy", 1);

// Paths
const p = (...segs) => path.join(__dirname, ...segs);
const PUBLIC_DIR = p("public");
const SESSIONS_DIR = process.env.SESSIONS_DIR || p("db");
if (!fs.existsSync(SESSIONS_DIR)) fs.mkdirSync(SESSIONS_DIR, { recursive: true });

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// Sesión
app.use(
  session({
    store: new SQLiteStore({ dir: SESSIONS_DIR, db: "sessions.sqlite" }),
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

// Healthcheck
app.get("/salud", (_req, res) => res.status(200).send("ok"));
app.get("/health", (_req, res) => res.status(200).send("ok"));

// ---- Login helpers ----
const LOGIN_CANDIDATES = [
  "login.html",
  "inicio de sesión.html", // con tilde
  "inicio de sesion.html", // sin tilde
  "inicio.html",
  "index.html",
];

function sendFirstExisting(res, baseDir, candidates) {
  for (const name of candidates) {
    const fp = path.join(baseDir, name);
    if (fs.existsSync(fp)) return res.sendFile(fp);
  }
  return res
    .status(404)
    .send("<h1>404</h1><p>No se encontró ninguna página de login (login.html / inicio de sesión.html / inicio.html / index.html).</p>");
}

// AUTH mínima (admin/admin como en tu versión)
const validateUser = async (username, password) => {
  if (username === "admin" && password === "admin") return { id: 1, username: "admin" };
  return null;
};

// Acepta múltiples nombres de campos y Basic Auth
function extractCreds(req) {
  let { username, password, user, pass, usuario, contraseña, contrasena, email, mail, pwd } = req.body || {};
  // Basic Auth
  if ((!username || !password) && req.headers.authorization?.startsWith("Basic ")) {
    try {
      const base64 = req.headers.authorization.split(" ")[1];
      const [u, p] = Buffer.from(base64, "base64").toString("utf8").split(":");
      username = username ?? u;
      password = password ?? p;
    } catch {}
  }
  username = username ?? user ?? usuario ?? email ?? mail;
  password = password ?? pass ?? contraseña ?? contrasena ?? pwd;
  // También permitimos query (solo para depuración)
  if ((!username || !password) && req.method === "GET") {
    const q = req.query || {};
    username = username ?? q.username ?? q.user ?? q.usuario ?? q.email ?? q.mail;
    password = password ?? q.password ?? q.pass ?? q.contraseña ?? q.contrasena ?? q.pwd;
  }
  return { username, password };
}

function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  // en vez de redirigir a un nombre fijo, servimos el login existente
  return sendFirstExisting(res, PUBLIC_DIR, LOGIN_CANDIDATES);
}

// Bloqueo acceso directo a HTML protegidos
const PROTECTED_HTML = new Set(["/inicio.html", "/historial.html"]);
app.use((req, res, next) => {
  if (PROTECTED_HTML.has(req.path) && (!req.session || !req.session.user)) {
    return sendFirstExisting(res, PUBLIC_DIR, LOGIN_CANDIDATES);
  }
  next();
});

// Rutas auth
app.all("/api/login", async (req, res) => {
  try {
    const { username, password } = extractCreds(req);
    if (!username || !password) {
      return res.status(400).json({
        ok: false,
        error: "Faltan credenciales. Envia username/password (o user/pass, usuario/contraseña, email/password).",
      });
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
app.get("/", (_req, res) => sendFirstExisting(res, PUBLIC_DIR, LOGIN_CANDIDATES));
app.get("/login", (_req, res) => sendFirstExisting(res, PUBLIC_DIR, LOGIN_CANDIDATES));
app.get("/inicio", requireAuth, (_req, res) => res.sendFile(path.join(PUBLIC_DIR, "inicio.html")));
app.get("/historial", requireAuth, (_req, res) => res.sendFile(path.join(PUBLIC_DIR, "historial.html")));

// Estáticos
app.use(
  express.static(PUBLIC_DIR, {
    extensions: ["html"],
    setHeaders(res, filePath) {
      if (filePath.endsWith(".html")) res.setHeader("Cache-Control", "no-store");
    },
  })
);

// 404
app.use((_req, res) => {
  res.status(404).send("<h1>404</h1><p>Recurso no encontrado.</p>");
});

app.listen(PORT, HOST, () => {
  console.log(`Servidor en http://${HOST}:${PORT} (env:${NODE_ENV})`);
});

