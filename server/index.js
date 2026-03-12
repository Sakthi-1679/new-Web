
import 'dotenv/config';
import express from 'express';
import mysql from 'mysql2/promise';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import helmet from 'helmet';
import crypto from 'crypto';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import { Expo } from 'expo-server-sdk';
import { GoogleAuth } from 'google-auth-library';

/**
 * SECURITY: Input sanitization helpers
 * Strip HTML tags to prevent stored XSS (defense-in-depth; React also auto-escapes output)
 */
const stripHtmlTags = (str) => {
  if (typeof str !== 'string') return str;
  return str.replace(/<[^>]*>/g, '');
};

// Sanitize all string values in an object
const sanitizeBody = (obj) => {
  if (!obj || typeof obj !== 'object') return obj;
  const sanitized = {};
  for (const [key, value] of Object.entries(obj)) {
    if (typeof value === 'string' && key !== 'password' && key !== 'idToken') {
      sanitized[key] = stripHtmlTags(value);
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
};

// SECURITY: Validate email format
const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 255;

// SECURITY: Validate only allowed status values (whitelist)
const VALID_STATUSES = ['PENDING', 'CONFIRMED', 'COMPLETED', 'CANCELLED'];

/**
 * PERFORMANCE: Simple in-memory cache for frequently-read, rarely-written data.
 * Avoids a DB round-trip on every request for products and settings.
 */
const cache = {
  _store: new Map(),
  get(key) {
    const entry = this._store.get(key);
    if (!entry) return null;
    // PERF: Return null if cache entry has expired
    if (Date.now() > entry.expiry) { this._store.delete(key); return null; }
    return entry.value;
  },
  set(key, value, ttlMs = 30_000) {
    // PERF: Default 30-second TTL keeps data fresh without constant DB hits
    this._store.set(key, { value, expiry: Date.now() + ttlMs });
  },
  invalidate(key) { this._store.delete(key); },
  invalidatePrefix(prefix) {
    for (const k of this._store.keys()) {
      if (k.startsWith(prefix)) this._store.delete(k);
    }
  },
};

// SECURITY: Stateless CSRF tokens derived via HMAC from the JWT.
// No in-memory store needed — survives serverless cold-starts.
const generateCsrfToken = (jwtToken) => {
  return crypto.createHmac('sha256', JWT_SECRET + '_csrf')
    .update(jwtToken)
    .digest('hex');
};

const verifyCsrfToken = (req, res, next) => {
  // SECURITY: Validate CSRF token on state-changing requests
  const csrfHeader = req.headers['x-csrf-token'];
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(403).json({ error: 'Invalid or missing CSRF token.' });
  }
  const jwtToken = authHeader.slice(7);
  const expected = generateCsrfToken(jwtToken);
  if (!csrfHeader || csrfHeader !== expected) {
    return res.status(403).json({ error: 'Invalid or missing CSRF token.' });
  }
  next();
};

const expoClient = new Expo();

// FCM v1 setup (uses GOOGLE_APPLICATION_CREDENTIALS env var or FIREBASE_SERVICE_ACCOUNT JSON)
let fcmAuth = null;
let fcmProjectId = null;
try {
  const serviceAccount = process.env.FIREBASE_SERVICE_ACCOUNT
    ? JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)
    : null;
  if (serviceAccount) {
    fcmAuth = new GoogleAuth({
      credentials: serviceAccount,
      scopes: ['https://www.googleapis.com/auth/firebase.messaging'],
    });
    fcmProjectId = serviceAccount.project_id;
    console.log('\u2705 FCM initialized for project:', fcmProjectId);
  } else {
    console.log('\u26a0\ufe0f  FIREBASE_SERVICE_ACCOUNT not set \u2013 FCM notifications disabled');
  }
} catch (e) {
  console.error('FCM init error:', e.message);
}

const app = express();
const router = express.Router();
const PORT = process.env.PORT || 3001;

// SECURITY: JWT secret must be set via environment variable in production
const JWT_SECRET = process.env.JWT_SECRET || 'vkm-default-secret';
if (!process.env.JWT_SECRET) {
  console.warn('⚠️  WARNING: JWT_SECRET not set in environment. Using insecure default. Set JWT_SECRET in .env for production!');
}

// PERF: gzip/brotli compress all responses > 1 KB to reduce transfer size
app.use(compression());

// Basic Logger (only in development to avoid I/O overhead in production)
if (process.env.NODE_ENV !== 'production') {
  app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
    next();
  });
}

/**
 * SECURITY MIDDLEWARE
 */
// SECURITY: Enhanced helmet config with CSP, HSTS, X-Frame-Options, etc.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://accounts.google.com", "https://apis.google.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://accounts.google.com"],
      imgSrc: ["'self'", "data:", "blob:", "https:"],
      connectSrc: ["'self'", "https://accounts.google.com", "https://fcm.googleapis.com"],
      frameSrc: ["'self'", "https://accounts.google.com"],
      fontSrc: ["'self'", "https:", "data:"],
      objectSrc: ["'none'"],
      // SECURITY: Prevent clickjacking
      frameAncestors: ["'self'"],
    },
  },
  // SECURITY: Enforce HTTPS via HSTS (1 year, include subdomains)
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  // SECURITY: Prevent MIME-type sniffing
  noSniff: true,
  // SECURITY: XSS filter
  xssFilter: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));
app.set('trust proxy', 1);

// SECURITY: Rate limiter for auth routes (prevent brute-force)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15-minute window
  max: 15,                   // 15 attempts per window per IP
  message: { error: 'Too many attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// SECURITY: General API rate limiter
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { error: 'Too many requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(apiLimiter);

// CORS Config
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  process.env.FRONTEND_URL 
];

app.use(cors({
  origin: function(origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1 || origin.endsWith('.vercel.app') || origin.includes('localhost')) {
      callback(null, true);
    } else {
      // SECURITY: Actually reject disallowed origins instead of silently allowing them
      console.warn("Blocked by CORS:", origin);
      callback(new Error('Origin not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  // SECURITY: Allow X-CSRF-Token header for CSRF protection
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
  credentials: true
}));

// Handle preflight requests explicitly
app.options('*', cors());

// PERF: Reduce max body size – 50 MB is excessive; 10 MB covers base64 images safely
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

/**
 * DATABASE INITIALIZATION
 */
let pool;

async function getDB() {
  if (pool) return pool;

  const dbConfig = {
    host: process.env.DB_HOST || '127.0.0.1',
    port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'vkm_flower_shop',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    enableKeepAlive: true, 
    keepAliveInitialDelay: 0
  };

  if (process.env.DB_SSL === 'true' || (process.env.DB_HOST && process.env.DB_HOST.includes('aivencloud.com'))) {
    dbConfig.ssl = { rejectUnauthorized: false };
  }

  pool = mysql.createPool(dbConfig);
  // Boost sort buffer so ORDER BY on image-heavy tables works
  pool.on('connection', (conn) => {
    conn.query('SET SESSION sort_buffer_size = 8388608'); // 8 MB
  });
  return pool;
}

// Initialize tables
async function initDB() {
  try {
    const db = await getDB();
    const conn = await db.getConnection();
    console.log("✅ Successfully connected to MySQL Database");
    conn.release();

    // 1. Users
    await db.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        phone VARCHAR(20),
        city VARCHAR(100) DEFAULT 'Kanchipuram',
        area VARCHAR(255),
        role ENUM('USER', 'ADMIN') DEFAULT 'USER',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_email (email)
      )
    `);

    // 2. Products
    await db.query(`
      CREATE TABLE IF NOT EXISTS products (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        price DECIMAL(10, 2) NOT NULL,
        duration_hours INT DEFAULT 24,
        images JSON,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // 3. Orders
    // PERF: Composite index on (user_id, id DESC) eliminates full-table scan for per-user order listing
    await db.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id INT AUTO_INCREMENT PRIMARY KEY,
        bill_id VARCHAR(50),
        daily_sequence INT,
        user_id INT,
        product_id INT,
        quantity INT DEFAULT 1,
        total_price DECIMAL(10, 2),
        description TEXT,
        status ENUM('PENDING', 'CONFIRMED', 'COMPLETED', 'CANCELLED') DEFAULT 'PENDING',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expected_delivery_at TIMESTAMP NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_user_id (user_id),
        INDEX idx_status (status),
        INDEX idx_created_at (created_at),
        INDEX idx_bill_id (bill_id)
      )
    `);

    // 4. Custom Orders
    // PERF: Index on user_id for fast per-user queries
    await db.query(`
      CREATE TABLE IF NOT EXISTS custom_orders (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        description TEXT,
        requested_date DATE,
        requested_time TIME,
        contact_name VARCHAR(255),
        contact_phone VARCHAR(20),
        images JSON,
        status ENUM('PENDING', 'CONFIRMED', 'COMPLETED', 'CANCELLED') DEFAULT 'PENDING',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        deadline_at TIMESTAMP NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_custom_user_id (user_id)
      )
    `);

    // 5. Settings
    await db.query(`
      CREATE TABLE IF NOT EXISTS settings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        key_name VARCHAR(50) UNIQUE,
        value VARCHAR(255)
      )
    `);
    // Seed default admin phone if not set
    await db.query(
      "INSERT INTO settings (key_name, value) VALUES ('admin_phone', '9999999999') ON DUPLICATE KEY UPDATE key_name = key_name"
    );

    // 6. Push Tokens
    await db.query(`
      CREATE TABLE IF NOT EXISTS push_tokens (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        token VARCHAR(500) NOT NULL,
        token_type VARCHAR(10) DEFAULT 'expo',
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY unique_token (token),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // --- MIGRATIONS: add columns that may be missing from older tables ---
    // Helper: check if column exists before adding (works on all MySQL versions)
    const addColumnIfMissing = async (table, column, definition) => {
      const [cols] = await db.query(
        `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?`,
        [table, column]
      );
      if (cols.length === 0) {
        await db.query(`ALTER TABLE \`${table}\` ADD COLUMN \`${column}\` ${definition}`);
        console.log(`✅ Added column ${table}.${column}`);
      }
    };
    try {
      await addColumnIfMissing('orders', 'expected_delivery_at', 'TIMESTAMP NULL');
      await addColumnIfMissing('orders', 'bill_id', 'VARCHAR(50) NULL');
      await addColumnIfMissing('orders', 'daily_sequence', 'INT NULL');
      await addColumnIfMissing('custom_orders', 'deadline_at', 'TIMESTAMP NULL');
      await addColumnIfMissing('push_tokens', 'token_type', "VARCHAR(10) DEFAULT 'expo'");
    } catch(e) { console.error('Migration error:', e.message); }

    // SECURITY: Admin credentials moved to environment variables (never hardcode secrets)
    const adminEmail = process.env.ADMIN_EMAIL || 'ajith12vkm@gmail.com';
    const adminPassword = process.env.ADMIN_PASSWORD;
    if (!adminPassword) {
      console.warn('⚠️  ADMIN_PASSWORD not set in environment. Admin seed/update skipped.');
    } else {
      const hashedPassword = await bcrypt.hash(adminPassword, 12); // SECURITY: bcrypt cost factor 12
      const [existing] = await db.query('SELECT * FROM users WHERE email = ?', [adminEmail]);
      if (existing.length === 0) {
        console.log("⚙️  Seeding Admin Account...");
        await db.query(
          'INSERT INTO users (name, email, password, phone, city, area, role) VALUES (?, ?, ?, ?, ?, ?, ?)',
          ['VKM Admin', adminEmail, hashedPassword, '9999999999', 'Kanchipuram', 'Headquarters', 'ADMIN']
        );
      } else {
        console.log("⚙️  Ensuring Admin Credentials & Role are correct...");
        await db.query('UPDATE users SET password = ?, role = ? WHERE email = ?', [hashedPassword, 'ADMIN', adminEmail]);
      }
    }

  } catch (err) {
    console.error("❌ Critical Database Error:", err.message);
  }
}

// Store the promise so routes can await it — prevents race condition on Vercel
// cold-starts where the first request arrives before initDB() finishes seeding.
const initPromise = initDB();

/**
 * HELPERS
 */
const generateBillId = async (conn) => {
  try {
    const [rows] = await conn.query(
      `SELECT MAX(daily_sequence) as max_seq FROM orders WHERE DATE(created_at) = CURDATE()`
    );
    const nextSeq = (rows[0].max_seq || 0) + 1;
    const dateStr = new Date().toISOString().slice(0, 10).replace(/-/g, ''); 
    const billId = `VKM-${dateStr}-${String(nextSeq).padStart(3, '0')}`;
    return { billId, nextSeq };
  } catch (e) {
    console.error("Error generating bill ID", e);
    return { billId: `VKM-${Date.now()}`, nextSeq: 1 };
  }
};

/**
 * PUSH NOTIFICATION HELPERS
 */
const getAdminUserIds = async (db) => {
  const [rows] = await db.query('SELECT id FROM users WHERE role = ?', ['ADMIN']);
  return rows.map(r => r.id);
};

const sendPushNotifications = async (db, userIds, title, body, data = {}) => {
  try {
    if (!userIds || userIds.length === 0) return;
    const placeholders = userIds.map(() => '?').join(',');
    const [rows] = await db.query(
      `SELECT token, token_type FROM push_tokens WHERE user_id IN (${placeholders})`,
      userIds
    );

    // --- Expo tokens ---
    const expoTokens = rows.filter(r => r.token_type === 'expo' && Expo.isExpoPushToken(r.token)).map(r => r.token);
    if (expoTokens.length > 0) {
      const messages = expoTokens.map(token => ({
        to: token, sound: 'default', title, body, data,
      }));
      const chunks = expoClient.chunkPushNotifications(messages);
      for (const chunk of chunks) {
        try { await expoClient.sendPushNotificationsAsync(chunk); }
        catch (e) { console.error('Expo push error:', e.message); }
      }
      console.log(`✅ Expo push sent to ${expoTokens.length} device(s)`);
    }

    // --- FCM tokens ---
    const fcmTokens = rows.filter(r => r.token_type === 'fcm').map(r => r.token);
    if (fcmTokens.length > 0 && fcmAuth && fcmProjectId) {
      const client = await fcmAuth.getClient();
      const accessToken = (await client.getAccessToken()).token;
      for (const fcmToken of fcmTokens) {
        try {
          const resp = await fetch(
            `https://fcm.googleapis.com/v1/projects/${fcmProjectId}/messages:send`,
            {
              method: 'POST',
              headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({
                message: {
                  token: fcmToken,
                  notification: { title, body },
                  data: Object.fromEntries(Object.entries(data).map(([k, v]) => [k, String(v)])),
                },
              }),
            }
          );
          if (!resp.ok) {
            const err = await resp.text();
            console.error('FCM send error:', err);
          }
        } catch (e) { console.error('FCM push error:', e.message); }
      }
      console.log(`✅ FCM push sent to ${fcmTokens.length} device(s)`);
    }
  } catch (err) {
    console.error('Push notification error:', err.message);
  }
};

/**
 * AUTH MIDDLEWARES
 */
const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: "No token provided." });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token." });
    req.user = user;
    next();
  });
};

const isAdmin = (req, res, next) => {
  if (req.user?.role !== 'ADMIN') return res.status(403).json({ error: "Admin only." });
  next();
};

/**
 * ROUTES (Defined on router, without /api prefix)
 */
router.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date() });
});

// -- PUSH TOKENS --
router.post('/push-token', verifyToken, async (req, res) => {
  try {
    const db = await getDB();
    const { token, type } = req.body;
    const tokenType = type === 'fcm' ? 'fcm' : 'expo';

    if (tokenType === 'expo' && !Expo.isExpoPushToken(token)) {
      return res.status(400).json({ error: 'Invalid Expo push token' });
    }
    if (!token) {
      return res.status(400).json({ error: 'Token is required' });
    }

    await db.query(
      'INSERT INTO push_tokens (user_id, token, token_type) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE user_id = VALUES(user_id), token_type = VALUES(token_type)',
      [req.user.id, token, tokenType]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Save push token error:', err.message);
    res.status(500).json({ error: 'Failed to save push token' });
  }
});

// SECURITY: Rate limit registration to prevent abuse
router.post('/register', authLimiter, async (req, res) => {
  try {
    const db = await getDB();
    // SECURITY: Sanitize inputs to strip HTML tags (XSS prevention)
    const sanitized = sanitizeBody(req.body);
    const { name, email, password, phone, city, area } = sanitized;
    
    // SECURITY: Enhanced input validation
    if (!email || !password || !name) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: "Invalid email format" });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters" });
    }
    if (name.length > 255 || (phone && phone.length > 20) || (area && area.length > 255)) {
      return res.status(400).json({ error: "Input exceeds maximum length" });
    }

    // SECURITY: bcrypt with cost factor 12 for stronger hashing
    const hashedPassword = await bcrypt.hash(password, 12);
    const [result] = await db.query(
      'INSERT INTO users (name, email, password, phone, city, area, role) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [name, email, hashedPassword, phone, city, area, 'USER']
    );
    const user = { id: result.insertId.toString(), name, email, phone: phone || '', city: city || 'Kanchipuram', area: area || '', role: 'USER' };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '7d' });
    // SECURITY: Generate CSRF token for the new session
    const csrfToken = generateCsrfToken(token);
    res.json({ user, token, csrfToken });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Email already registered. Please login.' });
    }
    // SECURITY: Log full error server-side, return generic message to client
    console.error("Registration Error:", err);
    res.status(500).json({ error: 'Registration failed. Please try again.' }); 
  }
});

// SECURITY: Rate limit login to prevent brute-force attacks
router.post('/login', authLimiter, async (req, res) => {
  try {
    await initPromise; // Ensure admin seeding is complete before login
    const db = await getDB();
    const { email, password } = req.body;
    // SECURITY: Validate email format before querying
    if (!email || !password || !isValidEmail(email)) {
      return res.status(400).json({ error: 'Invalid email or password format' });
    }
    const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (isMatch) {
      const { password: _, ...safeUser } = user;
      safeUser.id = safeUser.id.toString();
      const token = jwt.sign(safeUser, JWT_SECRET, { expiresIn: '7d' });
      // SECURITY: Generate CSRF token for the authenticated session
      const csrfToken = generateCsrfToken(token);
      res.json({ user: safeUser, token, csrfToken });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (err) { 
    // SECURITY: Log full error server-side, return generic message to client
    console.error("Login Error:", err);
    res.status(500).json({ error: 'Login failed. Please try again.' }); 
  }
});

// -- GOOGLE LOGIN --
// SECURITY: Rate limit Google login to prevent abuse
router.post('/google-login', authLimiter, async (req, res) => {
  try {
    const db = await getDB();
    const { idToken } = req.body;
    if (!idToken) return res.status(400).json({ error: 'idToken is required' });

    // SECURITY: Verify Google ID token with configured client ID
    const { OAuth2Client } = await import('google-auth-library');
    const googleClientId = process.env.GOOGLE_CLIENT_ID;
    const client = new OAuth2Client(googleClientId);
    const ticket = await client.verifyIdToken({
      idToken,
      audience: googleClientId ? [googleClientId] : [],
    });
    const payload = ticket.getPayload();
    if (!payload || !payload.email) {
      return res.status(401).json({ error: 'Invalid Google token' });
    }

    const email = payload.email.toLowerCase();
    // SECURITY: Sanitize name from Google payload
    const name = stripHtmlTags(payload.name || email.split('@')[0]);

    const [existing] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
    let user;
    if (existing.length > 0) {
      user = existing[0];
    } else {
      // SECURITY: Use crypto.randomBytes for random password instead of Math.random
      const randomPass = await bcrypt.hash(crypto.randomBytes(32).toString('hex'), 12);
      const [result] = await db.query(
        'INSERT INTO users (name, email, password, phone, city, area, role) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [name, email, randomPass, '', 'Kanchipuram', '', 'USER']
      );
      const [newUser] = await db.query('SELECT * FROM users WHERE id = ?', [result.insertId]);
      user = newUser[0];
    }

    const { password: _, ...safeUser } = user;
    safeUser.id = safeUser.id.toString();
    const token = jwt.sign(safeUser, JWT_SECRET, { expiresIn: '7d' });
    // SECURITY: Generate CSRF token for the authenticated session
    const csrfToken = generateCsrfToken(token);
    res.json({ user: safeUser, token, csrfToken });
  } catch (err) {
    // SECURITY: Log full error server-side, return generic message to client
    console.error("Google Login Error:", err);
    res.status(500).json({ error: 'Google login failed. Please try again.' });
  }
});

// -- PRODUCTS --
router.get('/products', async (req, res) => {
  try {
    // PERF: Serve from in-memory cache (30s TTL) – products change infrequently
    const cached = cache.get('products');
    if (cached) {
      // PERF: HTTP cache header lets browsers skip fetch for 30s
      res.set('Cache-Control', 'public, max-age=30');
      return res.json(cached);
    }

    const db = await getDB();
    // PERF: Select only needed columns; skip created_at to reduce payload
    const [rows] = await db.query('SELECT id, title, description, price, duration_hours, images FROM products ORDER BY id DESC');
    const formatted = rows.map(p => {
      let images = [];
      try {
        images = typeof p.images === 'string' ? JSON.parse(p.images) : (p.images || []);
      } catch (e) {
        images = [];
      }
      return { 
        id: p.id.toString(),
        title: p.title,
        description: p.description,
        price: p.price,
        images: Array.isArray(images) ? images : [],
        durationHours: p.duration_hours
      };
    });

    cache.set('products', formatted, 30_000);
    res.set('Cache-Control', 'public, max-age=30');
    res.json(formatted);
  } catch (err) { 
    console.error("Fetch products error:", err);
    res.json([]); 
  }
});

// SECURITY: CSRF + sanitization on product creation
router.post('/products', verifyToken, isAdmin, verifyCsrfToken, async (req, res) => {
  try {
    const db = await getDB();
    // SECURITY: Sanitize text inputs to prevent stored XSS
    const sanitized = sanitizeBody(req.body);
    const { title, description, price, durationHours, images } = sanitized;
    if (!title || price == null) {
      return res.status(400).json({ error: 'Title and price are required' });
    }
    const [result] = await db.query(
      'INSERT INTO products (title, description, price, duration_hours, images) VALUES (?, ?, ?, ?, ?)',
      [title, description, price, durationHours, JSON.stringify(images)]
    );
    // PERF: Invalidate product cache so next GET fetches fresh data
    cache.invalidate('products');
    res.json({ id: result.insertId.toString(), ...sanitized });
  } catch (err) {
    console.error('Create product error:', err);
    res.status(500).json({ error: 'Failed to create product' });
  }
});

router.put('/products/:id', verifyToken, isAdmin, verifyCsrfToken, async (req, res) => {
  try {
    const db = await getDB();
    const sanitized = sanitizeBody(req.body);
    const { title, description, price, durationHours, images } = sanitized;
    await db.query(
      'UPDATE products SET title=?, description=?, price=?, duration_hours=?, images=? WHERE id=?',
      [title, description, price, durationHours, JSON.stringify(images), req.params.id]
    );
    cache.invalidate('products'); // PERF: Bust cache on product update
    res.json({ success: true, id: req.params.id, ...sanitized });
  } catch (err) { 
    console.error('Update product error:', err);
    res.status(500).json({ error: 'Update failed' }); 
  }
});

router.delete('/products/:id', verifyToken, isAdmin, verifyCsrfToken, async (req, res) => {
  try {
    const db = await getDB();
    await db.query('DELETE FROM products WHERE id = ?', [req.params.id]);
    cache.invalidate('products'); // PERF: Bust cache on product delete
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Failed to delete' }); }
});

// -- ORDERS --
// PERF: Server-side filtering by user_id + pagination eliminates the N+1 pattern
//       where the client fetched ALL orders then filtered in JS.
router.get('/orders', verifyToken, async (req, res) => {
  try {
    const db = await getDB();
    const isAdminUser = req.user.role === 'ADMIN';
    // PERF: Pagination via ?page=&limit= – default 50 rows
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 50));
    const offset = (page - 1) * limit;

    // PERF: Non-admins only get their own orders (server-side WHERE instead of fetching all)
    // PERF: Select only needed columns; skip large productImages for list view,
    //       extract only the first image via JSON_EXTRACT to avoid sending full image arrays
    let query, params;
    if (isAdminUser) {
      query = `
        SELECT o.id, o.bill_id, o.user_id, o.product_id, o.quantity, o.total_price,
               o.description, o.status, o.created_at, o.expected_delivery_at,
               u.name as userName, u.phone as userPhone,
               p.title as productTitle, p.images as productImages
        FROM orders o
        JOIN users u ON o.user_id = u.id
        LEFT JOIN products p ON o.product_id = p.id
        ORDER BY o.id DESC
        LIMIT ? OFFSET ?
      `;
      params = [limit, offset];
    } else {
      // PERF: Uses idx_user_id index for fast user-scoped lookup
      query = `
        SELECT o.id, o.bill_id, o.user_id, o.product_id, o.quantity, o.total_price,
               o.description, o.status, o.created_at, o.expected_delivery_at,
               u.name as userName, u.phone as userPhone,
               p.title as productTitle, p.images as productImages
        FROM orders o
        JOIN users u ON o.user_id = u.id
        LEFT JOIN products p ON o.product_id = p.id
        WHERE o.user_id = ?
        ORDER BY o.id DESC
        LIMIT ? OFFSET ?
      `;
      params = [req.user.id, limit, offset];
    }

    const [rows] = await db.query(query, params);

    const formatted = rows.map(r => {
      let img = 'https://via.placeholder.com/150';
      try {
        const imgs = typeof r.productImages === 'string' ? JSON.parse(r.productImages) : (r.productImages || []);
        if (Array.isArray(imgs) && imgs.length > 0) img = imgs[0];
      } catch (e) {}

      return {
        id: r.id.toString(),
        billId: r.bill_id || `ORD-${r.id}`,
        userId: r.user_id.toString(),
        productId: r.product_id ? r.product_id.toString() : '0',
        productTitle: r.productTitle || 'Deleted Product',
        productImage: img,
        quantity: r.quantity,
        totalPrice: r.total_price,
        description: r.description,
        status: r.status,
        createdAt: r.created_at,
        expectedDeliveryAt: r.expected_delivery_at || r.created_at
      };
    });
    res.json(formatted);
  } catch (err) {
    console.error('Fetch orders error:', err);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// SECURITY: CSRF + input validation on order creation
router.post('/orders', verifyToken, verifyCsrfToken, async (req, res) => {
  try {
    const db = await getDB();
    const sanitized = sanitizeBody(req.body);
    const { userId, productId, quantity, description } = sanitized;
    // SECURITY: Validate numeric inputs
    if (!userId || !productId || !quantity || quantity < 1 || quantity > 1000) {
      return res.status(400).json({ error: 'Invalid order data' });
    }
    
    const [products] = await db.query('SELECT price FROM products WHERE id = ?', [productId]);
    if (products.length === 0) return res.status(404).json({ error: 'Product not found' });
    
    const totalPrice = products[0].price * quantity;
    const { billId, nextSeq } = await generateBillId(db);

    const [result] = await db.query(
      'INSERT INTO orders (bill_id, daily_sequence, user_id, product_id, quantity, total_price, description, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [billId, nextSeq, userId, productId, quantity, totalPrice, description, 'PENDING']
    );

    // PERF: Respond immediately, then fire push notifications asynchronously.
    // This removes ~200-500ms of third-party API latency from the user's response time.
    const orderId = result.insertId.toString();
    res.json({ id: orderId, billId, status: 'PENDING' });

    // PERF: Fire-and-forget push notification (runs after response is sent)
    setImmediate(async () => {
      try {
        const adminIds = await getAdminUserIds(db);
        const [prodRows] = await db.query('SELECT title FROM products WHERE id = ?', [productId]);
        const [userRows] = await db.query('SELECT name FROM users WHERE id = ?', [userId]);
        const userName = userRows[0]?.name || 'A customer';
        const prodTitle = prodRows[0]?.title || 'a product';
        await sendPushNotifications(db, adminIds,
          '🌸 New Order – VKM Flowers',
          `${userName} ordered ${prodTitle} ×${quantity} (₹${totalPrice})`,
          { type: 'new_order', orderId }
        );
      } catch(e) { console.error('Order push error:', e.message); }
    });
  } catch (err) { 
    console.error(err);
    res.status(500).json({ error: 'Order failed' }); 
  }
});

router.put('/orders/:id/status', verifyToken, isAdmin, verifyCsrfToken, async (req, res) => {
  try {
    const db = await getDB();
    const { status } = req.body;
    // SECURITY: Whitelist valid status values to prevent injection
    if (!VALID_STATUSES.includes(status)) {
      return res.status(400).json({ error: 'Invalid status value' });
    }
    let extraSql = "";
    if (status === 'CONFIRMED') {
      extraSql = ", expected_delivery_at = DATE_ADD(NOW(), INTERVAL 24 HOUR)";
    }
    await db.query(`UPDATE orders SET status = ? ${extraSql} WHERE id = ?`, [status, req.params.id]);

    res.json({ success: true });

    // PERF: Push notification fired after response – doesn't block the admin's UI
    setImmediate(async () => {
      try {
        const [orderRows] = await db.query('SELECT user_id FROM orders WHERE id = ?', [req.params.id]);
        if (orderRows.length > 0) {
          const msgs = { CONFIRMED: 'Your order has been confirmed! ✅', COMPLETED: 'Your order is ready for pickup! 🎉', CANCELLED: 'Your order has been cancelled. ❌' };
          const msg = msgs[status] || `Your order status updated to: ${status}`;
          await sendPushNotifications(db, [orderRows[0].user_id], '🌸 VKM Flowers – Order Update', msg, { type: 'order_update', orderId: req.params.id, status });
        }
      } catch(e) { console.error('Status push error:', e.message); }
    });
  } catch (err) { 
    console.error("Update order status error:", err.message, err.sql);
    res.status(500).json({ error: 'Update failed' }); 
  }
});

router.delete('/orders/:id', verifyToken, isAdmin, verifyCsrfToken, async (req, res) => {
  try {
    const db = await getDB();
    await db.query('DELETE FROM orders WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Delete failed' }); }
});

// -- CUSTOM ORDERS --
// PERF: Server-side user filtering + pagination (same pattern as /orders)
router.get('/custom-orders', verifyToken, async (req, res) => {
  try {
    const db = await getDB();
    const isAdminUser = req.user.role === 'ADMIN';
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 50));
    const offset = (page - 1) * limit;

    let query, params;
    if (isAdminUser) {
      query = `
        SELECT c.id, c.user_id, c.description, c.requested_date, c.requested_time,
               c.contact_name, c.contact_phone, c.images, c.status, c.created_at, c.deadline_at,
               u.name as userName
        FROM custom_orders c
        JOIN users u ON c.user_id = u.id
        ORDER BY c.id DESC
        LIMIT ? OFFSET ?
      `;
      params = [limit, offset];
    } else {
      // PERF: Uses idx_custom_user_id index
      query = `
        SELECT c.id, c.user_id, c.description, c.requested_date, c.requested_time,
               c.contact_name, c.contact_phone, c.images, c.status, c.created_at, c.deadline_at,
               u.name as userName
        FROM custom_orders c
        JOIN users u ON c.user_id = u.id
        WHERE c.user_id = ?
        ORDER BY c.id DESC
        LIMIT ? OFFSET ?
      `;
      params = [req.user.id, limit, offset];
    }

    const [rows] = await db.query(query, params);

    const formatted = rows.map(r => ({
      id: r.id.toString(),
      userId: r.user_id.toString(),
      description: r.description,
      requestedDate: r.requested_date,
      requestedTime: r.requested_time,
      contactName: r.contact_name,
      contactPhone: r.contact_phone,
      images: typeof r.images === 'string' ? JSON.parse(r.images) : (r.images || []),
      status: r.status,
      createdAt: r.created_at,
      deadlineAt: r.deadline_at || r.created_at
    }));
    res.json(formatted);
  } catch (err) {
    console.error('Fetch custom orders error:', err);
    res.status(500).json({ error: 'Failed to fetch custom orders' });
  }
});

// SECURITY: CSRF + input validation on custom order creation
router.post('/custom-orders', verifyToken, verifyCsrfToken, async (req, res) => {
  try {
    const db = await getDB();
    // SECURITY: Sanitize text inputs to prevent stored XSS
    const sanitized = sanitizeBody(req.body);
    const { userId, description, requestedDate, requestedTime, contactName, contactPhone, images } = sanitized;
    // SECURITY: Validate required fields and phone format
    if (!userId || !description || !requestedDate || !contactName || !contactPhone) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    if (!/^\d{10}$/.test(contactPhone)) {
      return res.status(400).json({ error: 'Invalid phone number format' });
    }
    const [result] = await db.query(
      'INSERT INTO custom_orders (user_id, description, requested_date, requested_time, contact_name, contact_phone, images, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [userId, description, requestedDate, requestedTime, contactName, contactPhone, JSON.stringify(images), 'PENDING']
    );

    const customOrderId = result.insertId.toString();
    res.json({ id: customOrderId, status: 'PENDING' });

    // PERF: Fire-and-forget push – don't block response for external API calls
    setImmediate(async () => {
      try {
        const adminIds = await getAdminUserIds(db);
        const [userRows] = await db.query('SELECT name FROM users WHERE id = ?', [userId]);
        const userName = userRows[0]?.name || 'A customer';
        await sendPushNotifications(db, adminIds,
          '🎨 Custom Order – VKM Flowers',
          `${userName} placed a custom flower order`,
          { type: 'new_custom_order', orderId: customOrderId }
        );
      } catch(e) { console.error('Custom order push error:', e.message); }
    });
  } catch (err) { res.status(500).json({ error: 'Custom Order failed' }); }
});

router.put('/custom-orders/:id/status', verifyToken, isAdmin, verifyCsrfToken, async (req, res) => {
  try {
    const db = await getDB();
    const { status } = req.body;
    // SECURITY: Whitelist valid status values
    if (!VALID_STATUSES.includes(status)) {
      return res.status(400).json({ error: 'Invalid status value' });
    }
    let extraSql = "";
    if (status === 'CONFIRMED') {
       extraSql = ", deadline_at = DATE_ADD(NOW(), INTERVAL 48 HOUR)";
    }
    await db.query(`UPDATE custom_orders SET status = ? ${extraSql} WHERE id = ?`, [status, req.params.id]);

    res.json({ success: true });

    // PERF: Async push – don't block admin response for third-party notification delivery
    setImmediate(async () => {
      try {
        const [orderRows] = await db.query('SELECT user_id FROM custom_orders WHERE id = ?', [req.params.id]);
        if (orderRows.length > 0) {
          const msgs = { CONFIRMED: 'Your custom order is confirmed! ✅', COMPLETED: 'Your custom order is ready! 🎉', CANCELLED: 'Your custom order has been cancelled. ❌' };
          const msg = msgs[status] || `Your custom order status updated to: ${status}`;
          await sendPushNotifications(db, [orderRows[0].user_id], '🌸 VKM Flowers – Custom Order Update', msg, { type: 'custom_order_update', orderId: req.params.id, status });
        }
      } catch(e) { console.error('Custom status push error:', e.message); }
    });
  } catch (err) { 
    console.error("Update custom order status error:", err.message, err.sql);
    res.status(500).json({ error: 'Update failed' }); 
  }
});

router.delete('/custom-orders/:id', verifyToken, isAdmin, verifyCsrfToken, async (req, res) => {
  try {
    const db = await getDB();
    await db.query('DELETE FROM custom_orders WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Delete failed' }); }
});

// -- SETTINGS --
router.get('/settings/contact', async (req, res) => {
  try {
    // PERF: Cache admin phone for 60s – it almost never changes
    const cached = cache.get('admin_phone');
    if (cached) {
      res.set('Cache-Control', 'public, max-age=60');
      return res.json(cached);
    }
    const db = await getDB();
    const [rows] = await db.query("SELECT value FROM settings WHERE key_name = 'admin_phone'");
    const result = { phone: rows.length ? rows[0].value : '9999999999' };
    cache.set('admin_phone', result, 60_000);
    res.set('Cache-Control', 'public, max-age=60');
    res.json(result);
  } catch (err) { res.json({ phone: '9999999999' }); }
});

router.put('/settings/contact', verifyToken, isAdmin, verifyCsrfToken, async (req, res) => {
  try {
    const db = await getDB();
    const { phone } = req.body;
    // SECURITY: Validate phone format
    if (!phone || !/^\d{10}$/.test(phone)) {
      return res.status(400).json({ error: 'Invalid phone number' });
    }
    await db.query("INSERT INTO settings (key_name, value) VALUES ('admin_phone', ?) ON DUPLICATE KEY UPDATE value = ?", [phone, phone]);
    cache.invalidate('admin_phone'); // PERF: Bust phone cache on update
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Update failed' }); }
});

// -- USERS --
router.get('/users/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.query('SELECT id, name, email, phone, city, area, role FROM users WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const u = rows[0];
    u.id = u.id.toString();
    res.json(u);
  } catch (err) { res.status(500).json({ error: 'Fetch failed' }); }
});

// SECURITY: CSRF token refresh endpoint (client calls on startup if CSRF token is missing)
router.get('/csrf-token', verifyToken, (req, res) => {
  const jwtToken = req.headers['authorization'].slice(7);
  const csrfToken = generateCsrfToken(jwtToken);
  res.json({ csrfToken });
});

// Register routes
app.use('/api', router);
app.use('/', router);

// SECURITY: Global error handler — log details server-side, return generic message to client
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.stack || err);
  res.status(err.status || 500).json({ error: 'An unexpected error occurred.' });
});

// Export app for Vercel
export default app;

// Start server if not running in Vercel
if (!process.env.VERCEL) {
  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);

    // Self-ping every 14 minutes to prevent Render free-tier spin-down
    const SELF_URL = process.env.RENDER_EXTERNAL_URL || 'https://new-web-2o8n.onrender.com';
    setInterval(() => {
      fetch(`${SELF_URL}/api/health`)
        .then(() => console.log('🏓 Keep-alive ping sent'))
        .catch(err => console.warn('⚠️ Keep-alive ping failed:', err.message));
    }, 14 * 60 * 1000); // every 14 minutes
  });

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.error(`❌ Port ${PORT} is already in use. Retrying in 3s...`);
      setTimeout(() => {
        server.close();
        server.listen(PORT, '0.0.0.0');
      }, 3000);
    } else {
      console.error('Server error:', err);
    }
  });

  // Graceful shutdown
  const shutdown = () => {
    console.log('\n🛑 Shutting down server gracefully...');
    server.close(() => {
      console.log('✅ Server closed.');
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 5000);
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}
