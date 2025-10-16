/**
 * server.js — versión final lista para Railway
 * Compatible con carpetas “public” o “público”
 * Maneja login flexible, sesión persistente y healthcheck.
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
const HOST = "0.0.0.0"; // necesario para Railway y PaaS

app.set("trust proxy", 1);

// === Detectar carpeta estática (public / público / publico) ===
const p = (...segs) => path.join(__dirname, ...segs);
const PUBLIC_DIR = (() => {
  const candidates = ["public", "público", "publico", "www", "dist"];
  for (const d of candidates) {
    const full = p(d);
    try {
      if (fs.existsSync(full) && fs.statSync(full).isDirectory()) return full;
    } catch {}
  }
  return p("public");
})();
console.log("📂 Carpeta estática usada:", PUBLIC_DIR);

// === Directorio para sesiones ===
const SESSIONS_DIR = process.env.SESSIONS_DIR || p("db");
if (!fs.existsSync(SESSIONS_DIR)) fs.mkdirSync(SESSIONS_DIR, { recursive: true });

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// === Configuración de sesión ===
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
      secure: IS_PROD, // cookies seguras en producción (TLS)
      maxAge: 1000 * 60 * 60 * 8, // 8 horas
    },
  })
);

// === Healthcheck para Railway ===
app.get("/salud", (_req, res) => res.status(200).send("ok"));
app.get("/health", (_req, res) => res.status(200).send("ok"));

// === Función para servir el primer archivo existente ===
function sendFirstExisting(res, baseDir, candidates, notFoundMsg) {
  for (const name of candidates) {
    const fp = path.join(baseDir, name);
    if (fs.existsSync(fp)) return res.sendFile(fp);
  }
  return res.status(404).send(`<h1>404</h1><p>${notFoundMsg}</p>`);
}

// === Login flexible ===
const validateUser = async (username, password) => {
  if (username === "admin" && password === "admin") return { id: 1, username: "admin" };
  return null;
};

function extractCreds(req) {
  let { username, password, user, pass, usuario, contraseña, contrasena, email, mail, pwd } =
    req.body || {};
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
  return { username, password };
}

function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return sendFirstExisting(
    res,
    PUBLIC_DIR,
    ["login.html", "inicio de sesión.html", "inicio de sesion.html", "index.html"],
    "No se encontró página de login."
  );
}

// === HTML protegidos ===
const PROTECTED_HTML = new Set(["/inicio.html", "/historial.html"]);
app.use((req, res, next) => {
  if (PROTECTED_HTML.has(req.path) && (!req.session || !req.session.user)) {
    return sendFirstExisting(
      res,
      PUBLIC_DIR,
      ["login.html", "inicio de sesión.html", "inicio de sesion.html", "index.html"],
      "No se encontró página de login."
    );
  }
  next();
});

// === API: login/logout/me ===
app.all("/api/login", async (req, res) => {
  try {
    const { username, password } = extractCreds(req);
    if (!username || !password) {
      return res.status(400).json({ ok: false, error: "Faltan credenciales." });
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

// === Endpoint que usa tu HTML para verificar sesión ===
app.get("/verificar-sesion", (req, res) => {
  if (!req.session || !req.session.user) return res.status(401).json({ activo: false });
  res.json({ activo: true, user: req.session.user });
});

// === Páginas HTML ===
const LOGIN_CANDIDATES = ["login.html", "inicio de sesión.html", "inicio de sesion.html", "index.html"];
const INICIO_CANDIDATES = ["inicio.html", "Inicio.html", "home.html", "dashboard.html"];

app.get("/", (_req, res) =>
  sendFirstExisting(res, PUBLIC_DIR, LOGIN_CANDIDATES, "No se encontró la página de login.")
);
app.get("/login", (_req, res) =>
  sendFirstExisting(res, PUBLIC_DIR, LOGIN_CANDIDATES, "No se encontró la página de login.")
);
app.get(/^\/inicio(?:\.html)?$/i, requireAuth, (req, res) =>
  sendFirstExisting(res, PUBLIC_DIR, INICIO_CANDIDATES, "No se encontró la página de inicio.")
);
app.get("/historial", requireAuth, (req, res) =>
  res.sendFile(path.join(PUBLIC_DIR, "historial.html"))
);

// === Archivos estáticos ===
app.use(
  express.static(PUBLIC_DIR, {
    extensions: ["html"],
    setHeaders(res, filePath) {
      if (filePath.endsWith(".html")) res.setHeader("Cache-Control", "no-store");
    },
  })
);

// === Log de 404 (debug) ===
app.use((req, res, next) => {
  res.on("finish", () => {
    if (res.statusCode === 404) console.log("[404]", req.method, req.originalUrl);
  });
  next();
});

// === 404 genérico ===
app.use((_req, res) => {
  res.status(404).send("<h1>404</h1><p>Recurso no encontrado.</p>");
});

app.listen(PORT, HOST, () => {
  console.log(`🚀 Servidor activo en http://${HOST}:${PORT} (env:${NODE_ENV})`);
});


