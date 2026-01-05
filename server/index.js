
import 'dotenv/config';
import express from 'express';
import mysql from 'mysql2/promise';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import helmet from 'helmet';

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'vkm-default-secret';

// Basic Logger
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

/**
 * SECURITY MIDDLEWARE
 */
app.use(helmet()); 
app.set('trust proxy', 1);

// CORS Config
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5173',
  process.env.FRONTEND_URL 
];

app.use(cors({
  origin: function(origin, callback) {
    if (!origin) return callback(null, true);
    // Allow requests from allowed origins, vercel apps, or localhost for dev
    if (allowedOrigins.indexOf(origin) !== -1 || origin.endsWith('.vercel.app') || origin.includes('localhost')) {
      callback(null, true);
    } else {
      console.log("Blocked by CORS:", origin);
      callback(null, true); // Permissive for initial setup, restrict later if needed
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

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
        INDEX idx_status (status),
        INDEX idx_created_at (created_at),
        INDEX idx_bill_id (bill_id)
      )
    `);

    // 4. Custom Orders
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
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
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

    // Seed Admin
    const adminEmail = 'ajith12vkm@gmail.com';
    const [existingAdmin] = await db.query('SELECT * FROM users WHERE email = ?', [adminEmail]);
    
    if (existingAdmin.length === 0) {
      console.log("⚙️  Seeding Admin Account...");
      const hashedPassword = await bcrypt.hash('vkmajith@12', 10);
      await db.query(
        'INSERT INTO users (name, email, password, phone, city, area, role) VALUES (?, ?, ?, ?, ?, ?, ?)',
        ['VKM Admin', adminEmail, hashedPassword, '9999999999', 'Kanchipuram', 'Headquarters', 'ADMIN']
      );
    }

  } catch (err) {
    console.error("❌ Critical Database Error:", err.message);
  }
}

initDB();

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
 * ROUTES
 */
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date() });
});

app.post('/api/register', async (req, res) => {
  try {
    const db = await getDB();
    const { name, email, password, phone, city, area } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await db.query(
      'INSERT INTO users (name, email, password, phone, city, area, role) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [name, email, hashedPassword, phone, city, area, 'USER']
    );
    const user = { id: result.insertId.toString(), name, email, role: 'USER' };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '7d' });
    res.json({ user, token });
  } catch (err) { 
    res.status(500).json({ error: 'Registration failed or Email already exists' }); 
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const db = await getDB();
    const { email, password } = req.body;
    const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (isMatch) {
      const { password: _, ...safeUser } = user;
      safeUser.id = safeUser.id.toString();
      const token = jwt.sign(safeUser, JWT_SECRET, { expiresIn: '7d' });
      res.json({ user: safeUser, token });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (err) { res.status(500).json({ error: 'Login failed' }); }
});

// -- PRODUCTS --
app.get('/api/products', async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.query('SELECT * FROM products ORDER BY created_at DESC');
    res.json(rows.map(p => ({ 
      ...p, 
      id: p.id.toString(), 
      images: typeof p.images === 'string' ? JSON.parse(p.images) : p.images,
      durationHours: p.duration_hours
    })));
  } catch (err) { res.json([]); }
});

app.post('/api/products', verifyToken, isAdmin, async (req, res) => {
  try {
    const db = await getDB();
    const { title, description, price, durationHours, images } = req.body;
    const [result] = await db.query(
      'INSERT INTO products (title, description, price, duration_hours, images) VALUES (?, ?, ?, ?, ?)',
      [title, description, price, durationHours, JSON.stringify(images)]
    );
    res.json({ id: result.insertId.toString(), ...req.body });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/products/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const db = await getDB();
    await db.query('DELETE FROM products WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Failed to delete' }); }
});

// -- ORDERS --
app.get('/api/orders', verifyToken, async (req, res) => {
  try {
    const db = await getDB();
    let query = `
      SELECT o.*, u.name as userName, u.phone as userPhone, p.title as productTitle, p.images as productImages 
      FROM orders o 
      JOIN users u ON o.user_id = u.id 
      LEFT JOIN products p ON o.product_id = p.id 
      ORDER BY o.created_at DESC
    `;
    const [rows] = await db.query(query);
    
    const formatted = rows.map(r => {
      let img = 'https://via.placeholder.com/150';
      try {
        const imgs = typeof r.productImages === 'string' ? JSON.parse(r.productImages) : r.productImages;
        if (imgs && imgs.length > 0) img = imgs[0];
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
    console.error(err);
    res.status(500).json({ error: err.message }); 
  }
});

app.post('/api/orders', verifyToken, async (req, res) => {
  try {
    const db = await getDB();
    const { userId, productId, quantity, description } = req.body;
    
    const [products] = await db.query('SELECT price FROM products WHERE id = ?', [productId]);
    if (products.length === 0) return res.status(404).json({ error: 'Product not found' });
    
    const totalPrice = products[0].price * quantity;
    const { billId, nextSeq } = await generateBillId(db);

    const [result] = await db.query(
      'INSERT INTO orders (bill_id, daily_sequence, user_id, product_id, quantity, total_price, description, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [billId, nextSeq, userId, productId, quantity, totalPrice, description, 'PENDING']
    );
    res.json({ id: result.insertId.toString(), billId, status: 'PENDING' });
  } catch (err) { 
    console.error(err);
    res.status(500).json({ error: 'Order failed' }); 
  }
});

app.put('/api/orders/:id/status', verifyToken, isAdmin, async (req, res) => {
  try {
    const db = await getDB();
    const { status } = req.body;
    let extraSql = "";
    if (status === 'CONFIRMED') {
      extraSql = ", expected_delivery_at = DATE_ADD(NOW(), INTERVAL 24 HOUR)";
    }
    await db.query(`UPDATE orders SET status = ? ${extraSql} WHERE id = ?`, [status, req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Update failed' }); }
});

app.delete('/api/orders/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const db = await getDB();
    await db.query('DELETE FROM orders WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Delete failed' }); }
});

// -- CUSTOM ORDERS --
app.get('/api/custom-orders', verifyToken, async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.query(`
      SELECT c.*, u.name as userName 
      FROM custom_orders c 
      JOIN users u ON c.user_id = u.id 
      ORDER BY c.created_at DESC
    `);
    
    const formatted = rows.map(r => ({
      id: r.id.toString(),
      userId: r.user_id.toString(),
      description: r.description,
      requestedDate: r.requested_date,
      requestedTime: r.requested_time,
      contactName: r.contact_name,
      contactPhone: r.contact_phone,
      images: typeof r.images === 'string' ? JSON.parse(r.images) : r.images,
      status: r.status,
      createdAt: r.created_at,
      deadlineAt: r.deadline_at || r.created_at
    }));
    res.json(formatted);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/custom-orders', verifyToken, async (req, res) => {
  try {
    const db = await getDB();
    const { userId, description, requestedDate, requestedTime, contactName, contactPhone, images } = req.body;
    const [result] = await db.query(
      'INSERT INTO custom_orders (user_id, description, requested_date, requested_time, contact_name, contact_phone, images, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [userId, description, requestedDate, requestedTime, contactName, contactPhone, JSON.stringify(images), 'PENDING']
    );
    res.json({ id: result.insertId.toString(), status: 'PENDING' });
  } catch (err) { res.status(500).json({ error: 'Custom Order failed' }); }
});

app.put('/api/custom-orders/:id/status', verifyToken, isAdmin, async (req, res) => {
  try {
    const db = await getDB();
    const { status } = req.body;
    let extraSql = "";
    if (status === 'CONFIRMED') {
       extraSql = ", deadline_at = DATE_ADD(NOW(), INTERVAL 48 HOUR)";
    }
    await db.query(`UPDATE custom_orders SET status = ? ${extraSql} WHERE id = ?`, [status, req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Update failed' }); }
});

app.delete('/api/custom-orders/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const db = await getDB();
    await db.query('DELETE FROM custom_orders WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Delete failed' }); }
});

// -- SETTINGS --
app.get('/api/settings/contact', async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.query("SELECT value FROM settings WHERE key_name = 'admin_phone'");
    res.json({ phone: rows.length ? rows[0].value : '9999999999' });
  } catch (err) { res.json({ phone: '9999999999' }); }
});

app.put('/api/settings/contact', verifyToken, isAdmin, async (req, res) => {
  try {
    const db = await getDB();
    const { phone } = req.body;
    await db.query("INSERT INTO settings (key_name, value) VALUES ('admin_phone', ?) ON DUPLICATE KEY UPDATE value = ?", [phone, phone]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Update failed' }); }
});

// -- USERS --
app.get('/api/users/:id', verifyToken, isAdmin, async (req, res) => {
  try {
    const db = await getDB();
    const [rows] = await db.query('SELECT id, name, email, phone, city, area, role FROM users WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const u = rows[0];
    u.id = u.id.toString();
    res.json(u);
  } catch (err) { res.status(500).json({ error: 'Fetch failed' }); }
});

// START SERVER (Render)
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
