/**
 * server.js — versión completa con protecciones:
 * 1) Obliga a pasar por "/" antes de ver "/inicio".
 * 2) Bloquea el acceso directo a archivos sensibles servidos como estáticos (p.ej. /inicio.html).
 *
 * Requisitos:
 *   npm i express express-session connect-sqlite3
 *
 * Variables de entorno recomendadas (Railway):
 *   SESSION_SECRET=un_secreto_largo_y_unico
 *   NODE_ENV=production
 */

const path = require("path");
const fs = require("fs");
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);

const app = express();

// ====== Config básica ======
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || "development";
const IS_PROD = NODE_ENV === "production";
const PUBLIC_DIR = path.join(__dirname, "public");

// Si estás detrás de proxy (Railway), confía en el proxy para HTTPS y IP reales
app.set("trust proxy", 1);

// Parseo de body (por si usas formularios / JSON)
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ====== Sesiones ======
app.use(
  session({
    name: "sid",
    secret: process.env.SESSION_SECRET || "CAMBIA_ESTE_SECRETO",
    resave: false,
    saveUninitialized: true,
    store: new SQLiteStore({
      // El archivo de sesiones vive fuera de public/
      db: "sessions.sqlite",
      dir: path.join(__dirname, ".data"),
    }),
    cookie: {
      httpOnly: true,
      sameSite: IS_PROD ? "none" : "lax",
      secure: IS_PROD, // true en producción (HTTPS en Railway)
      maxAge: 1000 * 60 * 60 * 8, // 8 horas
    },
  })
);

// ====== Helpers / Middlewares ======

/**
 * Marca que el usuario "pasó por la landing" ("/")
 * y exige esa marca para ver /inicio.
 */
function requireLanding(req, res, next) {
  if (req.session?.pasoLanding) return next();
  // Si no pasó por "/", redirige a la landing
  const url = new URL(`${req.protocol}://${req.get("host")}${req.originalUrl}`);
  // Puedes adjuntar "next" si quieres volver luego: /?next=/inicio
  return res.redirect(`/?next=${encodeURIComponent(url.pathname)}`);
}

/**
 * (Opcional) Requiere sesión autenticada.
 * Si no manejas login/usuarios, puedes dejarlo pasar con next().
 * Si SÍ usas login, ajusta esta validación a tu lógica real.
 */
function requiereSesionUnica(req, res, next) {
  // Ejemplo genérico: considera autenticado si existe req.session.usuario o req.session.autenticado
  if (req.session?.usuario || req.session?.autenticado) return next();
  // Si NO usas login, comenta la línea siguiente para no bloquear:
  // return res.redirect("/");
  return next();
}

// ====== Rutas ======

// Landing "/" — marca que se pasó por aquí y sirve tu login/landing
app.get("/", (req, res) => {
  // Marca de paso por la landing
  req.session.pasoLanding = true;

  // Sirve tu login.html o contenido de landing
  const loginFile = path.join(PUBLIC_DIR, "login.html");
  if (fs.existsSync(loginFile)) {
    return res.sendFile(loginFile);
  }
  // Fallback mínimo si no existe login.html
  res.send(`<h1>Landing</h1><p>Has pasado por la landing. <a href="/inicio">Ir a inicio</a></p>`);
});

// Ejemplo de endpoint POST de login (AJUSTA a tu lógica real si lo usas)
app.post("/login", (req, res) => {
  const { usuario } = req.body;
  if (usuario && String(usuario).trim()) {
    req.session.usuario = usuario.trim();
    req.session.autenticado = true;
    return res.redirect("/inicio");
  }
  return res.redirect("/");
});

// Página protegida "/inicio" — requiere haber pasado por "/"
// (y opcionalmente estar autenticado si activas ese guard)
app.get("/inicio", requireLanding, requiereSesionUnica, (req, res) => {
  const inicioFile = path.join(PUBLIC_DIR, "inicio.html");
  if (fs.existsSync(inicioFile)) {
    return res.sendFile(inicioFile);
  }
  // Fallback mínimo si no existe inicio.html
  res.send(`<h1>Inicio</h1><p>Bienvenido${req.session.usuario ? ", " + req.session.usuario : ""}.</p>`);
});

// (Opcional) Otra página protegida, p.ej. "/historial"
app.get("/historial", requireLanding, requiereSesionUnica, (req, res) => {
  const f = path.join(PUBLIC_DIR, "historial.html");
  if (fs.existsSync(f)) return res.sendFile(f);
  res.send("<h1>Historial</h1>");
});

// ====== Protección de archivos estáticos sensibles ======
//
// Si sirves public/ con express.static, por defecto cualquiera podría pedir
// /inicio.html directamente. Interceptamos esas rutas ANTES del estático.
const archivosProtegidos = new Set([
  "/inicio.html",
  "/historial.html",
  // agrega aquí otros archivos que NO quieras exponer directos:
  // "/panel.html", "/privado.html", ...
]);

app.use((req, res, next) => {
  if (archivosProtegidos.has(req.path)) {
    // Exigir haber pasado por "/" y (opcional) estar autenticado
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
  console.log(`Servidor escuchando en http://localhost:${PORT} (env: ${NODE_ENV})`);
});

