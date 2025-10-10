/**
 * server.js — versión completa con corrección de SQLite en Railway
 * y protecciones de acceso a /inicio y archivos estáticos sensibles.
 *
 * Requisitos:
 *   npm i express express-session connect-sqlite3 sqlite3
 *
 * Variables de entorno recomendadas:
 *   SESSION_SECRET=un_secreto_largo_y_unico
 *   NODE_ENV=production
 *   (Opcional) SESSIONS_DIR=/data/sessions  -> si montas un Volume en /data
 */

const path = require("path");
const fs = require("fs");
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);

const app = express();

// ====== Config básica ======
const PORT = process.env.PORT || 8080;
const NODE_ENV = process.env.NODE_ENV || "development";
const IS_PROD = NODE_ENV === "production";
const PUBLIC_DIR = path.join(__dirname, "public");

// Confía en proxy (Railway)
app.set("trust proxy", 1);

// Body parsers
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ====== Sesiones (con ruta escribible garantizada) ======
const DEFAULT_SESSIONS_DIR =
  process.env.SESSIONS_DIR ||
  (fs.existsSync("/data") ? "/data/sessions" : "/tmp/sessions"); // /data si hay volumen, si no /tmp

// Asegura que la carpeta existe antes de abrir SQLite
try {
  fs.mkdirSync(DEFAULT_SESSIONS_DIR, { recursive: true });
  console.log(`[sesiones] Carpeta de sesiones: ${DEFAULT_SESSIONS_DIR}`);
} catch (e) {
  console.error("[sesiones] No se pudo crear la carpeta de sesiones:", e);
  // fallback duro a /tmp/sessions
  try {
    fs.mkdirSync("/tmp/sessions", { recursive: true });
    console.log("[sesiones] Usando fallback /tmp/sessions");
  } catch (e2) {
    console.error("[sesiones] Falló también /tmp/sessions:", e2);
  }
}

app.use(
  session({
    name: "sid",
    secret: process.env.SESSION_SECRET || "CAMBIA_ESTE_SECRETO",
    resave: false,
    saveUninitialized: true,
    store: new SQLiteStore({
      db: "sessions.sqlite",
      dir: fs.existsSync(DEFAULT_SESSIONS_DIR)
        ? DEFAULT_SESSIONS_DIR
        : "/tmp/sessions",
    }),
    cookie: {
      httpOnly: true,
      sameSite: IS_PROD ? "none" : "lax",
      secure: IS_PROD, // true en producción (HTTPS)
      maxAge: 1000 * 60 * 60 * 8, // 8 horas
    },
  })
);

// ====== Helpers / Middlewares ======

/**
 * Exige haber pasado por la landing ("/").
 */
function requireLanding(req, res, next) {
  if (req.session?.pasoLanding) return next();
  const url = new URL(`${req.protocol}://${req.get("host")}${req.originalUrl}`);
  return res.redirect(`/?next=${encodeURIComponent(url.pathname)}`);
}

/**
 * (Opcional) Requiere sesión autenticada.
 * Ajusta a tu lógica real si tienes login. Ahora mismo deja pasar si no usas login.
 */
function requiereSesionUnica(req, res, next) {
  if (req.session?.usuario || req.session?.autenticado) return next();
  // Si NO usas login, no bloquees:
  return next();
  // Si SÍ quieres bloquear cuando no haya login, usa:
  // return res.redirect("/");
}

// ====== Rutas ======

// Landing "/" — marca que se pasó por aquí y sirve tu login/landing
app.get("/", (req, res) => {
  req.session.pasoLanding = true;

  const loginFile = path.join(PUBLIC_DIR, "login.html");
  if (fs.existsSync(loginFile)) {
    return res.sendFile(loginFile);
  }
  res.send(
    `<h1>Landing</h1><p>Has pasado por la landing. <a href="/inicio">Ir a inicio</a></p>`
  );
});

// Ejemplo de login (ajústalo a tu caso real)
app.post("/login", (req, res) => {
  const { usuario } = req.body;
  if (usuario && String(usuario).trim()) {
    req.session.usuario = String(usuario).trim();
    req.session.autenticado = true;
    return res.redirect("/inicio");
  }
  return res.redirect("/");
});

// Página protegida "/inicio"
app.get("/inicio", requireLanding, requiereSesionUnica, (req, res) => {
  const inicioFile = path.join(PUBLIC_DIR, "inicio.html");
  if (fs.existsSync(inicioFile)) {
    return res.sendFile(inicioFile);
  }
  res.send(
    `<h1>Inicio</h1><p>Bienvenido${
      req.session.usuario ? ", " + req.session.usuario : ""
    }.</p>`
  );
});

// (Opcional) Otra página protegida
app.get("/historial", requireLanding, requiereSesionUnica, (req, res) => {
  const f = path.join(PUBLIC_DIR, "historial.html");
  if (fs.existsSync(f)) return res.sendFile(f);
  res.send("<h1>Historial</h1>");
});

// ====== Protección de archivos estáticos sensibles ======
// Intercepta rutas a archivos que no deben verse directos.
const archivosProtegidos = new Set([
  "/inicio.html",
  "/historial.html",
  // agrega aquí otros archivos sensibles si los tienes:
  // "/panel.html", "/privado.html", ...
]);

app.use((req, res, next) => {
  if (archivosProtegidos.has(req.path)) {
    return requireLanding(req, res, () => requiereSesionUnica(req, res, next));
  }
  next();
});

// ====== Servir estáticos (después de la protección) ======
app.use(
  express.static(PUBLIC_DIR, {
    index: false, // evita servir automáticamente /index.html
    extensions: ["html"], // permite /ruta -> /ruta.html si existe
    fallthrough: true,
  })
);

// ====== Logout (opcional) ======
app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("sid");
    res.redirect("/");
  });
});

// ====== 404 ======
app.use((req, res) => {
  res.status(404).send("<h1>404</h1><p>Recurso no encontrado.</p>");
});

// ====== Arranque ======
app.listen(PORT, () => {
  console.log(
    `Servidor escuchando en http://localhost:${PORT} (env:${NODE_ENV})`
  );
});
