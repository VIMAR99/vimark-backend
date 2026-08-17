const express = require("express");
const cors = require("cors");
const Database = require("better-sqlite3");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { FedaPay, Transaction } = require("fedapay");

FedaPay.setApiKey(process.env.FEDAPAY_SECRET_KEY);
FedaPay.setEnvironment("sandbox");
const app = express();
const db = new Database("vimark.db");

const PORT = process.env.PORT || 3000;
const SECRET =
  process.env.JWT_SECRET || "CHANGE_ME_IN_PRODUCTION";

app.use(cors());
app.use(express.json());

db.pragma("journal_mode=WAL");

/* =========================
   DATABASE
========================= */

db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT UNIQUE,
  email TEXT UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'student',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS businesses(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  location TEXT DEFAULT '',
  verified INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS products(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  business_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  price INTEGER NOT NULL,
  image_url TEXT DEFAULT '',
  stock INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS courses(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  subject TEXT NOT NULL,
  level TEXT NOT NULL,
  description TEXT DEFAULT '',
  is_premium INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS subscriptions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  plan TEXT NOT NULL,
  status TEXT DEFAULT 'active',
  amount INTEGER NOT NULL,
  started_at TEXT DEFAULT CURRENT_TIMESTAMP,
  expires_at TEXT
);
`);

/* =========================
   HELPERS
========================= */

const hash = (password) =>
  crypto
    .createHash("sha256")
    .update(password)
    .digest("hex");

const token = (user) =>
  jwt.sign(
    {
      id: user.id,
      role: user.role,
      name: user.name
    },
    SECRET,
    {
      expiresIn: "7d"
    }
  );

function auth(req, res, next) {
  const header = req.headers.authorization || "";

  const t = header.startsWith("Bearer ")
    ? header.slice(7)
    : null;

  if (!t) {
    return res.status(401).json({
      error: "Authentification requise"
    });
  }

  try {
    req.user = jwt.verify(t, SECRET);
    next();
  } catch (e) {
    return res.status(401).json({
      error: "Token invalide ou expiré"
    });
  }
}

function merchantOnly(req, res, next) {
  if (req.user.role !== "merchant") {
    return res.status(403).json({
      error: "Réservé aux commerçants"
    });
  }

  next();
}

/* =========================
   HEALTH
========================= */

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "VIMARK API",
    version: "0.2.0"
  });
});

/* =========================
   REGISTER
========================= */

app.post("/api/auth/register", (req, res) => {
  const {
    name,
    phone,
    email,
    password,
    role = "student"
  } = req.body;

  if (!name || !password) {
    return res.status(400).json({
      error: "Nom et mot de passe requis"
    });
  }

  if (
    !["student", "merchant", "teacher"].includes(role)
  ) {
    return res.status(400).json({
      error: "Rôle invalide"
    });
  }

  try {
    const r = db
      .prepare(`
        INSERT INTO users(
          name,
          phone,
          email,
          password_hash,
          role
        )
        VALUES(?,?,?,?,?)
      `)
      .run(
        name,
        phone || null,
        email || null,
        hash(password),
        role
      );

    const u = db
      .prepare(`
        SELECT id,name,phone,email,role
        FROM users
        WHERE id=?
      `)
      .get(r.lastInsertRowid);

    res.status(201).json({
      user: u,
      token: token(u)
    });
  } catch (e) {
    res.status(409).json({
      error: "Téléphone ou e-mail déjà utilisé"
    });
  }
});

/* =========================
   LOGIN
========================= */

app.post("/api/auth/login", (req, res) => {
  const {
    identifier,
    password
  } = req.body;

  const u = db
    .prepare(`
      SELECT *
      FROM users
      WHERE phone=? OR email=?
    `)
    .get(identifier, identifier);

  if (
    !u ||
    u.password_hash !== hash(password || "")
  ) {
    return res.status(401).json({
      error: "Identifiants incorrects"
    });
  }

  const safe = {
    id: u.id,
    name: u.name,
    phone: u.phone,
    email: u.email,
    role: u.role
  };

  res.json({
    user: safe,
    token: token(safe)
  });
});

/* =========================
   CURRENT USER
========================= */

app.get("/api/me", auth, (req, res) => {
  const user = db
    .prepare(`
      SELECT id,name,phone,email,role,created_at
      FROM users
      WHERE id=?
    `)
    .get(req.user.id);

  if (!user) {
    return res.status(404).json({
      error: "Utilisateur introuvable"
    });
  }

  res.json(user);
});

/* =========================
   UPDATE PROFILE
========================= */

app.put("/api/me", auth, (req, res) => {
  const {
    name,
    phone,
    email
  } = req.body;

  if (!name || !name.trim()) {
    return res.status(400).json({
      error: "Le nom est requis"
    });
  }

  try {
    db.prepare(`
      UPDATE users
      SET
        name=?,
        phone=?,
        email=?
      WHERE id=?
    `).run(
      name.trim(),
      phone || null,
      email || null,
      req.user.id
    );

    const user = db
      .prepare(`
        SELECT id,name,phone,email,role,created_at
        FROM users
        WHERE id=?
      `)
      .get(req.user.id);

    res.json(user);
  } catch (e) {
    res.status(409).json({
      error: "Téléphone ou e-mail déjà utilisé"
    });
  }
});

/* =========================
   COURSES - GET
========================= */

app.get("/api/courses", (req, res) => {
  let sql =
    "SELECT * FROM courses WHERE 1=1";

  const params = [];

  if (req.query.subject) {
    sql += " AND subject=?";
    params.push(req.query.subject);
  }

  if (req.query.level) {
    sql += " AND level=?";
    params.push(req.query.level);
  }

  sql += " ORDER BY id DESC";

  res.json(
    db.prepare(sql).all(...params)
  );
});

/* =========================
   COURSES - CREATE
========================= */

app.post(
  "/api/courses",
  auth,
  (req, res) => {
    if (req.user.role !== "teacher") {
      return res.status(403).json({
        error: "Réservé aux enseignants"
      });
    }

    const {
      title,
      subject,
      level,
      description = "",
      is_premium = 0
    } = req.body;

    if (!title || !subject || !level) {
      return res.status(400).json({
        error: "Titre, matière et niveau requis"
      });
    }

    const r = db
      .prepare(`
        INSERT INTO courses(
          title,
          subject,
          level,
          description,
          is_premium
        )
        VALUES(?,?,?,?,?)
      `)
      .run(
        title,
        subject,
        level,
        description,
        is_premium ? 1 : 0
      );

    const course = db
      .prepare(`
        SELECT *
        FROM courses
        WHERE id=?
      `)
      .get(r.lastInsertRowid);

    res.status(201).json(course);
  }
);

/* =========================
   BUSINESS - CREATE
========================= */

app.post(
  "/api/businesses",
  auth,
  merchantOnly,
  (req, res) => {
    const {
      name,
      description = "",
      location = ""
    } = req.body;

    if (!name || !name.trim()) {
      return res.status(400).json({
        error: "Nom de boutique requis"
      });
    }

    const existing = db
      .prepare(`
        SELECT *
        FROM businesses
        WHERE user_id=?
      `)
      .get(req.user.id);

    if (existing) {
      return res.status(409).json({
        error: "Vous avez déjà une boutique"
      });
    }

    const r = db
      .prepare(`
        INSERT INTO businesses(
          user_id,
          name,
          description,
          location
        )
        VALUES(?,?,?,?)
      `)
      .run(
        req.user.id,
        name.trim(),
        description,
        location
      );

    const business = db
      .prepare(`
        SELECT *
        FROM businesses
        WHERE id=?
      `)
      .get(r.lastInsertRowid);

    res.status(201).json(business);
  }
);

/* =========================
   BUSINESS - MY STORE
========================= */

app.get(
  "/api/businesses/me",
  auth,
  merchantOnly,
  (req, res) => {
    const business = db
      .prepare(`
        SELECT *
        FROM businesses
        WHERE user_id=?
      `)
      .get(req.user.id);

    if (!business) {
      return res.status(404).json({
        error: "Aucune boutique trouvée"
      });
    }

    res.json(business);
  }
);

/* =========================
   BUSINESS - UPDATE
========================= */

app.put(
  "/api/businesses/me",
  auth,
  merchantOnly,
  (req, res) => {
    const {
      name,
      description = "",
      location = ""
    } = req.body;

    if (!name || !name.trim()) {
      return res.status(400).json({
        error: "Nom de boutique requis"
      });
    }

    const business = db
      .prepare(`
        SELECT *
        FROM businesses
        WHERE user_id=?
      `)
      .get(req.user.id);

    if (!business) {
      return res.status(404).json({
        error: "Boutique introuvable"
      });
    }

    db.prepare(`
      UPDATE businesses
      SET
        name=?,
        description=?,
        location=?
      WHERE id=? AND user_id=?
    `).run(
      name.trim(),
      description,
      location,
      business.id,
      req.user.id
    );

    const updated = db
      .prepare(`
        SELECT *
        FROM businesses
        WHERE id=?
      `)
      .get(business.id);

    res.json(updated);
  }
);

/* =========================
   PRODUCTS - PUBLIC
========================= */

app.get("/api/products", (req, res) => {
  if (req.query.search) {
    const q =
      `%${req.query.search}%`;

    const products = db
      .prepare(`
        SELECT
          p.*,
          b.name AS business_name,
          b.location
        FROM products p
        JOIN businesses b
          ON b.id=p.business_id
        WHERE p.name LIKE ?
           OR p.description LIKE ?
        ORDER BY p.id DESC
      `)
      .all(q, q);

    return res.json(products);
  }

  const products = db
    .prepare(`
      SELECT
        p.*,
        b.name AS business_name,
        b.location
      FROM products p
      JOIN businesses b
        ON b.id=p.business_id
      ORDER BY p.id DESC
    `)
    .all();

  res.json(products);
});

/* =========================
   PRODUCTS - MY PRODUCTS
========================= */

app.get(
  "/api/products/me",
  auth,
  merchantOnly,
  (req, res) => {
    const products = db
      .prepare(`
        SELECT
          p.*,
          b.name AS business_name
        FROM products p
        JOIN businesses b
          ON b.id=p.business_id
        WHERE b.user_id=?
        ORDER BY p.id DESC
      `)
      .all(req.user.id);

    res.json(products);
  }
);

/* =========================
   PRODUCT - CREATE
========================= */

app.post(
  "/api/products",
  auth,
  merchantOnly,
  (req, res) => {
    const {
      business_id,
      name,
      description = "",
      price,
      image_url = "",
      stock = 0
    } = req.body;

    const business = db
      .prepare(`
        SELECT *
        FROM businesses
        WHERE id=? AND user_id=?
      `)
      .get(
        business_id,
        req.user.id
      );

    if (!business) {
      return res.status(403).json({
        error: "Boutique inaccessible"
      });
    }

    if (
      !name ||
      !Number.isInteger(price)
    ) {
      return res.status(400).json({
        error: "Nom et prix requis"
      });
    }

    const r = db
      .prepare(`
        INSERT INTO products(
          business_id,
          name,
          description,
          price,
          image_url,
          stock
        )
        VALUES(?,?,?,?,?,?)
      `)
      .run(
        business_id,
        name.trim(),
        description,
        price,
        image_url,
        stock
      );

    const product = db
      .prepare(`
        SELECT *
        FROM products
        WHERE id=?
      `)
      .get(r.lastInsertRowid);

    res.status(201).json(product);
  }
);

/* =========================
   PRODUCT - UPDATE
========================= */

app.put(
  "/api/products/:id",
  auth,
  merchantOnly,
  (req, res) => {
    const productId =
      Number(req.params.id);

    const product = db
      .prepare(`
        SELECT p.*
        FROM products p
        JOIN businesses b
          ON b.id=p.business_id
        WHERE p.id=?
          AND b.user_id=?
      `)
      .get(
        productId,
        req.user.id
      );

    if (!product) {
      return res.status(404).json({
        error: "Produit introuvable"
      });
    }

    const {
      name = product.name,
      description = product.description,
      price = product.price,
      image_url = product.image_url,
      stock = product.stock
    } = req.body;

    if (
      !name ||
      !Number.isInteger(price)
    ) {
      return res.status(400).json({
        error: "Nom et prix requis"
      });
    }

    db.prepare(`
      UPDATE products
      SET
        name=?,
        description=?,
        price=?,
        image_url=?,
        stock=?
      WHERE id=?
    `).run(
      name.trim(),
      description,
      price,
      image_url,
      stock,
      productId
    );

    const updated = db
      .prepare(`
        SELECT *
        FROM products
        WHERE id=?
      `)
      .get(productId);

    res.json(updated);
  }
);

/* =========================
   PRODUCT - DELETE
========================= */

app.delete(
  "/api/products/:id",
  auth,
  merchantOnly,
  (req, res) => {
    const productId =
      Number(req.params.id);

    const product = db
      .prepare(`
        SELECT p.id
        FROM products p
        JOIN businesses b
          ON b.id=p.business_id
        WHERE p.id=?
          AND b.user_id=?
      `)
      .get(
        productId,
        req.user.id
      );

    if (!product) {
      return res.status(404).json({
        error: "Produit introuvable"
      });
    }

    db.prepare(`
      DELETE FROM products
      WHERE id=?
    `).run(productId);

    res.json({
      success: true,
      message: "Produit supprimé"
    });
  }
);
/* =========================
   FEDAPAY - CREATE PAYMENT
========================= */

app.post(
  "/api/payments/fedapay",
  auth,
  async (req, res) => {
    try {
      const {
        amount = 1500,
        description = "VIMARK Premium"
      } = req.body;

      const transaction = await Transaction.create({
        description,
        amount,
        currency: {
          iso: "XOF"
        }
      });

      const token =
        await transaction.generateToken();

      res.status(201).json({
        success: true,
        token,
        transaction
      });

    } catch (error) {
      console.error(
        "FedaPay error:",
        error
      );

      res.status(500).json({
        error:
          "Impossible de créer la transaction FedaPay"
      });
    }
  }
);
/* =========================
   SUBSCRIPTIONS - CREATE
========================= */

app.post(
  "/api/subscriptions",
  auth,
  (req, res) => {
    const {
      plan = "premium",
      amount = 1500
    } = req.body;

    if (
      !["premium", "premium_plus"]
        .includes(plan)
    ) {
      return res.status(400).json({
        error: "Plan invalide"
      });
    }

    const r = db
      .prepare(`
        INSERT INTO subscriptions(
          user_id,
          plan,
          status,
          amount,
          expires_at
        )
        VALUES(
          ?,
          ?,
          'active',
          ?,
          datetime('now','+30 days')
        )
      `)
      .run(
        req.user.id,
        plan,
        amount
      );

    const subscription = db
      .prepare(`
        SELECT *
        FROM subscriptions
        WHERE id=?
      `)
      .get(r.lastInsertRowid);

    res.status(201).json({
      success: true,
      message:
        "Paiement simulé et abonnement activé",
      subscription
    });
  }
);

/* =========================
   SUBSCRIPTIONS - ME
========================= */

app.get(
  "/api/subscriptions/me",
  auth,
  (req, res) => {
    const subscriptions = db
      .prepare(`
        SELECT *
        FROM subscriptions
        WHERE user_id=?
        ORDER BY id DESC
      `)
      .all(req.user.id);

    res.json(subscriptions);
  }
);

/* =========================
   START SERVER
========================= */

app.listen(PORT, () => {
  console.log(
    `VIMARK API running on port ${PORT}`
  );
});
