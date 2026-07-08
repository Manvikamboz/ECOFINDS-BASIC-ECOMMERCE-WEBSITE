const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

// ─── Fail fast on missing env vars ────────────────────────────────────────────
const REQUIRED_ENV = ['JWT_SECRET', 'DB_HOST', 'DB_PORT', 'DB_USER', 'DB_PASSWORD', 'DB_NAME'];
for (const key of REQUIRED_ENV) {
    if (!process.env[key]) {
        console.error(`❌ Missing required environment variable: ${key}`);
        process.exit(1);
    }
}

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Security headers (helmet) ─────────────────────────────────────────────────
app.use(helmet({
    contentSecurityPolicy: false // index.html uses inline scripts
}));

// ─── CORS — restrict to your domain ───────────────────────────────────────────
app.use(cors({
    origin: process.env.ALLOWED_ORIGIN || `http://localhost:${PORT}`,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// ─── Rate limiting ─────────────────────────────────────────────────────────────
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10,
    message: { error: 'Too many requests, please try again in 15 minutes' },
    standardHeaders: true,
    legacyHeaders: false
});

const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 100,
    message: { error: 'Rate limit exceeded' }
});

// ─── Uploads directory ─────────────────────────────────────────────────────────
const uploadsDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// ─── Multer storage ────────────────────────────────────────────────────────────
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname).toLowerCase());
    }
});

const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];

const fileFilter = (req, file, cb) => {
    if (!ALLOWED_MIME_TYPES.includes(file.mimetype)) {
        return cb(new Error('Only image files (JPG, PNG, GIF, WEBP) are allowed'), false);
    }
    cb(null, true);
};

const upload = multer({
    storage,
    fileFilter,
    limits: { fileSize: 5 * 1024 * 1024 } // 5 MB
});

// ─── Body parsing (limit JSON size to prevent DoS) ────────────────────────────
app.use(express.json({ limit: '10kb' }));
app.use(express.static('public'));
app.use('/uploads', express.static(uploadsDir));

// Apply general rate limit to all API routes
app.use('/api/', apiLimiter);

// ─── Database connection pool ──────────────────────────────────────────────────
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT) || 3306,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

async function connectDB() {
    try {
        const conn = await pool.getConnection();
        console.log('✅ Connected to MySQL database');
        conn.release();
    } catch (error) {
        console.error('❌ Database connection failed:', error.message);
        process.exit(1);
    }
}

// ─── Validation helpers ────────────────────────────────────────────────────────
const VALID_CATEGORIES = ['Electronics', 'Clothing', 'Home & Garden', 'Books', 'Sports', 'Toys', 'Other'];
const CATEGORY_EMOJIS = {
    'Electronics': '📱', 'Clothing': '👕', 'Home & Garden': '🏡',
    'Books': '📖', 'Sports': '⚽', 'Toys': '🧸', 'Other': '📦'
};

function validateEmail(email) {
    return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validatePassword(password) {
    return typeof password === 'string' && password.length >= 8;
}

function validateUsername(username) {
    return typeof username === 'string' && username.trim().length >= 3 && username.trim().length <= 50;
}

// ─── JWT middleware ────────────────────────────────────────────────────────────
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access token required' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token' });
        req.user = user;
        next();
    });
};

// Helper to safely delete an uploaded file (non-blocking)
function deleteUploadedFile(filePath) {
    if (filePath && filePath.startsWith('/uploads/')) {
        const fullPath = path.join(__dirname, 'public', filePath);
        fs.promises.unlink(fullPath).catch(() => {}); // ignore if already gone
    }
}

// ==========================================
// API ROUTES
// ==========================================

// ─── Register ─────────────────────────────────────────────────────────────────
app.post('/api/register', authLimiter, async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!validateUsername(username)) {
            return res.status(400).json({ error: 'Username must be 3–50 characters' });
        }
        if (!validateEmail(email)) {
            return res.status(400).json({ error: 'Invalid email address' });
        }
        if (!validatePassword(password)) {
            return res.status(400).json({ error: 'Password must be at least 8 characters' });
        }

        const cleanUsername = username.trim();

        const [existing] = await pool.execute(
            'SELECT id FROM users WHERE email = ? OR username = ?',
            [email, cleanUsername]
        );
        if (existing.length > 0) {
            return res.status(400).json({ error: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        const [result] = await pool.execute(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            [cleanUsername, email, hashedPassword]
        );

        const token = jwt.sign(
            { id: result.insertId, username: cleanUsername, email },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({ success: true, token, user: { id: result.insertId, username: cleanUsername, email } });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// ─── Login ────────────────────────────────────────────────────────────────────
app.post('/api/login', authLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!validateEmail(email)) {
            return res.status(400).json({ error: 'Invalid email address' });
        }
        if (!password || typeof password !== 'string') {
            return res.status(400).json({ error: 'Password is required' });
        }

        const [users] = await pool.execute(
            'SELECT id, username, email, password FROM users WHERE email = ?',
            [email]
        );

        // Timing-safe: always run bcrypt.compare even if user not found
        const DUMMY_HASH = '$2b$12$invalid.hash.for.timing.attack.prevention.000000000000';
        const storedHash = users.length > 0 ? users[0].password : DUMMY_HASH;
        const validPassword = await bcrypt.compare(password, storedHash);

        if (users.length === 0 || !validPassword) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        const user = users[0];
        const token = jwt.sign(
            { id: user.id, username: user.username, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({ success: true, token, user: { id: user.id, username: user.username, email: user.email } });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// ─── Get All Products (with pagination) ───────────────────────────────────────
app.get('/api/products', async (req, res) => {
    try {
        const { search, category } = req.query;
        const page = Math.max(1, parseInt(req.query.page) || 1);
        const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
        const offset = (page - 1) * limit;

        let query = `
            SELECT p.*, u.username as seller_username
            FROM products p
            JOIN users u ON p.seller_id = u.id
            WHERE 1=1
        `;
        let params = [];

        if (search && typeof search === 'string') {
            const safe = search.substring(0, 100);
            query += ' AND (p.title LIKE ? OR p.description LIKE ?)';
            params.push(`%${safe}%`, `%${safe}%`);
        }

        if (category && VALID_CATEGORIES.includes(category)) {
            query += ' AND p.category = ?';
            params.push(category);
        }

        query += ' ORDER BY p.created_at DESC LIMIT ? OFFSET ?';
        params.push(limit, offset);

        const [products] = await pool.execute(query, params);
        res.json(products);
    } catch (error) {
        console.error('Get products error:', error);
        res.status(500).json({ error: 'Failed to fetch products' });
    }
});

// ─── Get Single Product ────────────────────────────────────────────────────────
app.get('/api/products/:id', async (req, res) => {
    try {
        const productId = parseInt(req.params.id);
        if (isNaN(productId)) return res.status(400).json({ error: 'Invalid product ID' });

        const [products] = await pool.execute(
            `SELECT p.*, u.username as seller_username
             FROM products p
             JOIN users u ON p.seller_id = u.id
             WHERE p.id = ?`,
            [productId]
        );

        if (products.length === 0) return res.status(404).json({ error: 'Product not found' });
        res.json(products[0]);
    } catch (error) {
        console.error('Get product error:', error);
        res.status(500).json({ error: 'Failed to fetch product' });
    }
});

// ─── Create Product ────────────────────────────────────────────────────────────
app.post('/api/products', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        const { title, description, category, price } = req.body;

        if (!title || typeof title !== 'string' || title.trim().length < 3 || title.trim().length > 200) {
            return res.status(400).json({ error: 'Title must be 3–200 characters' });
        }
        if (!description || typeof description !== 'string' || description.trim().length < 10) {
            return res.status(400).json({ error: 'Description must be at least 10 characters' });
        }
        if (!VALID_CATEGORIES.includes(category)) {
            return res.status(400).json({ error: 'Invalid category' });
        }
        const parsedPrice = parseFloat(price);
        if (isNaN(parsedPrice) || parsedPrice < 0 || parsedPrice > 999999) {
            return res.status(400).json({ error: 'Price must be between 0 and 999,999' });
        }

        const sellerId = req.user.id;
        const imagePath = req.file
            ? `/uploads/${req.file.filename}`
            : (CATEGORY_EMOJIS[category] || '📦');

        const [result] = await pool.execute(
            'INSERT INTO products (title, description, category, price, seller_id, image) VALUES (?, ?, ?, ?, ?, ?)',
            [title.trim(), description.trim(), category, parsedPrice, sellerId, imagePath]
        );

        res.json({
            success: true,
            product: {
                id: result.insertId, title: title.trim(), description: description.trim(),
                category, price: parsedPrice, seller_id: sellerId, image: imagePath
            }
        });
    } catch (error) {
        console.error('Create product error:', error);
        res.status(500).json({ error: 'Failed to create product' });
    }
});

// ─── Update Product ────────────────────────────────────────────────────────────
app.put('/api/products/:id', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        const productId = parseInt(req.params.id);
        if (isNaN(productId)) return res.status(400).json({ error: 'Invalid product ID' });

        const { title, description, category, price } = req.body;
        const userId = req.user.id;

        if (!title || typeof title !== 'string' || title.trim().length < 3 || title.trim().length > 200) {
            return res.status(400).json({ error: 'Title must be 3–200 characters' });
        }
        if (!description || typeof description !== 'string' || description.trim().length < 10) {
            return res.status(400).json({ error: 'Description must be at least 10 characters' });
        }
        if (!VALID_CATEGORIES.includes(category)) {
            return res.status(400).json({ error: 'Invalid category' });
        }
        const parsedPrice = parseFloat(price);
        if (isNaN(parsedPrice) || parsedPrice < 0 || parsedPrice > 999999) {
            return res.status(400).json({ error: 'Price must be between 0 and 999,999' });
        }

        const [products] = await pool.execute(
            'SELECT seller_id, image FROM products WHERE id = ?',
            [productId]
        );

        if (products.length === 0) return res.status(404).json({ error: 'Product not found' });
        if (products[0].seller_id !== userId) return res.status(403).json({ error: 'Not authorized' });

        let imagePath = products[0].image;
        if (req.file) {
            deleteUploadedFile(products[0].image); // delete old file asynchronously
            imagePath = `/uploads/${req.file.filename}`;
        }

        await pool.execute(
            'UPDATE products SET title = ?, description = ?, category = ?, price = ?, image = ? WHERE id = ?',
            [title.trim(), description.trim(), category, parsedPrice, imagePath, productId]
        );

        res.json({ success: true });
    } catch (error) {
        console.error('Update product error:', error);
        res.status(500).json({ error: 'Failed to update product' });
    }
});

// ─── Delete Product ────────────────────────────────────────────────────────────
app.delete('/api/products/:id', authenticateToken, async (req, res) => {
    try {
        const productId = parseInt(req.params.id);
        if (isNaN(productId)) return res.status(400).json({ error: 'Invalid product ID' });

        const userId = req.user.id;

        const [products] = await pool.execute(
            'SELECT seller_id, image FROM products WHERE id = ?',
            [productId]
        );

        if (products.length === 0) return res.status(404).json({ error: 'Product not found' });
        if (products[0].seller_id !== userId) return res.status(403).json({ error: 'Not authorized' });

        deleteUploadedFile(products[0].image);

        // Cascade cleanup: remove from all carts before deleting product
        await pool.execute('DELETE FROM cart WHERE product_id = ?', [productId]);
        await pool.execute('DELETE FROM products WHERE id = ?', [productId]);

        res.json({ success: true });
    } catch (error) {
        console.error('Delete product error:', error);
        res.status(500).json({ error: 'Failed to delete product' });
    }
});

// ─── Get My Products ───────────────────────────────────────────────────────────
app.get('/api/my-products', authenticateToken, async (req, res) => {
    try {
        const [products] = await pool.execute(
            'SELECT * FROM products WHERE seller_id = ? ORDER BY created_at DESC',
            [req.user.id]
        );
        res.json(products);
    } catch (error) {
        console.error('Get user products error:', error);
        res.status(500).json({ error: 'Failed to fetch products' });
    }
});

// ─── Cart: GET ─────────────────────────────────────────────────────────────────
app.get('/api/cart', authenticateToken, async (req, res) => {
    try {
        const [cartItems] = await pool.execute(
            `SELECT c.*, p.title, p.price, p.image
             FROM cart c
             JOIN products p ON c.product_id = p.id
             WHERE c.user_id = ?`,
            [req.user.id]
        );
        res.json(cartItems);
    } catch (error) {
        console.error('Get cart error:', error);
        res.status(500).json({ error: 'Failed to fetch cart' });
    }
});

// ─── Cart: POST ────────────────────────────────────────────────────────────────
app.post('/api/cart', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const parsedProductId = parseInt(req.body.productId);
        const parsedQuantity = parseInt(req.body.quantity) || 1;

        if (isNaN(parsedProductId)) return res.status(400).json({ error: 'Invalid product ID' });
        if (parsedQuantity < 1 || parsedQuantity > 100) {
            return res.status(400).json({ error: 'Quantity must be between 1 and 100' });
        }

        // Verify product exists and user is NOT the seller
        const [productRows] = await pool.execute(
            'SELECT id, seller_id FROM products WHERE id = ?',
            [parsedProductId]
        );
        if (productRows.length === 0) return res.status(404).json({ error: 'Product not found' });
        if (productRows[0].seller_id === userId) {
            return res.status(400).json({ error: 'You cannot add your own product to cart' });
        }

        const [existing] = await pool.execute(
            'SELECT id FROM cart WHERE user_id = ? AND product_id = ?',
            [userId, parsedProductId]
        );

        if (existing.length > 0) {
            await pool.execute(
                'UPDATE cart SET quantity = quantity + ? WHERE user_id = ? AND product_id = ?',
                [parsedQuantity, userId, parsedProductId]
            );
        } else {
            await pool.execute(
                'INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, ?)',
                [userId, parsedProductId, parsedQuantity]
            );
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Add to cart error:', error);
        res.status(500).json({ error: 'Failed to add to cart' });
    }
});

// ─── Cart: DELETE ──────────────────────────────────────────────────────────────
app.delete('/api/cart/:productId', authenticateToken, async (req, res) => {
    try {
        const productId = parseInt(req.params.productId);
        if (isNaN(productId)) return res.status(400).json({ error: 'Invalid product ID' });

        await pool.execute(
            'DELETE FROM cart WHERE user_id = ? AND product_id = ?',
            [req.user.id, productId]
        );
        res.json({ success: true });
    } catch (error) {
        console.error('Remove from cart error:', error);
        res.status(500).json({ error: 'Failed to remove from cart' });
    }
});

// ─── Checkout (transactional) ──────────────────────────────────────────────────
app.post('/api/checkout', authenticateToken, async (req, res) => {
    const conn = await pool.getConnection();
    try {
        await conn.beginTransaction();
        const userId = req.user.id;

        const [cartItems] = await conn.execute(
            `SELECT c.*, p.price
             FROM cart c
             JOIN products p ON c.product_id = p.id
             WHERE c.user_id = ?`,
            [userId]
        );

        if (cartItems.length === 0) {
            await conn.rollback();
            return res.status(400).json({ error: 'Cart is empty' });
        }

        const total = cartItems.reduce((sum, item) => sum + (parseFloat(item.price) * item.quantity), 0);

        const [orderResult] = await conn.execute(
            'INSERT INTO orders (user_id, total) VALUES (?, ?)',
            [userId, total.toFixed(2)]
        );

        const orderId = orderResult.insertId;

        for (const item of cartItems) {
            await conn.execute(
                'INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)',
                [orderId, item.product_id, item.quantity, item.price]
            );
        }

        await conn.execute('DELETE FROM cart WHERE user_id = ?', [userId]);

        await conn.commit();
        res.json({ success: true, orderId });
    } catch (error) {
        await conn.rollback();
        console.error('Checkout error:', error);
        res.status(500).json({ error: 'Checkout failed' });
    } finally {
        conn.release();
    }
});

// ─── Get Orders ────────────────────────────────────────────────────────────────
app.get('/api/orders', authenticateToken, async (req, res) => {
    try {
        const [orders] = await pool.execute(
            `SELECT o.*,
                    GROUP_CONCAT(CONCAT(oi.quantity, 'x ', p.title) SEPARATOR ', ') as items
             FROM orders o
             LEFT JOIN order_items oi ON o.id = oi.order_id
             LEFT JOIN products p ON oi.product_id = p.id
             WHERE o.user_id = ?
             GROUP BY o.id
             ORDER BY o.order_date DESC`,
            [req.user.id]
        );
        res.json(orders);
    } catch (error) {
        console.error('Get orders error:', error);
        res.status(500).json({ error: 'Failed to fetch orders' });
    }
});

// ─── Update Profile ────────────────────────────────────────────────────────────
app.put('/api/profile', authenticateToken, async (req, res) => {
    try {
        const { username, email } = req.body;
        const userId = req.user.id;

        if (!validateUsername(username)) {
            return res.status(400).json({ error: 'Username must be 3–50 characters' });
        }
        if (!validateEmail(email)) {
            return res.status(400).json({ error: 'Invalid email address' });
        }

        const [existing] = await pool.execute(
            'SELECT id FROM users WHERE (username = ? OR email = ?) AND id != ?',
            [username.trim(), email, userId]
        );

        if (existing.length > 0) {
            return res.status(400).json({ error: 'Username or email already taken' });
        }

        await pool.execute(
            'UPDATE users SET username = ?, email = ? WHERE id = ?',
            [username.trim(), email, userId]
        );

        res.json({ success: true });
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

// ─── Global error handler ──────────────────────────────────────────────────────
app.use((err, req, res, next) => {
    if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ error: 'File too large. Maximum size is 5MB.' });
    }
    if (err.message && err.message.includes('image')) {
        return res.status(400).json({ error: err.message });
    }
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// ─── Start: local dev vs Vercel serverless ─────────────────────────────────────
if (require.main === module) {
    // Running directly with `node server.js` or `npm start`
    connectDB().then(() => {
        app.listen(PORT, () => {
            console.log(`🌱 EcoFinds server running on port ${PORT}`);
        });
    });
} else {
    // Running as a Vercel serverless function — export app directly
    // Pool auto-connects lazily on first query
    module.exports = app;
}