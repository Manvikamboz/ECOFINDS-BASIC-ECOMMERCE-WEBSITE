const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Multer configuration for image uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadsDir);
    },
    filename: function (req, file, cb) {
        // Generate unique filename with timestamp and random number
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

// File filter for images only
const fileFilter = (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
        cb(null, true);
    } else {
        cb(new Error('Only image files are allowed!'), false);
    }
};

const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // Serve frontend files
app.use('/uploads', express.static(uploadsDir)); // Serve uploaded images

// Database connection
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || 'manvi',
    database: process.env.DB_NAME || 'ecofinds'
};

let db;

async function connectDB() {
    try {
        db = await mysql.createConnection(dbConfig);
        console.log('Connected to MySQL database');
    } catch (error) {
        console.error('Database connection failed:', error);
        process.exit(1);
    }
}

// JWT middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// ==========================================
// API ROUTES
// ==========================================

// User Registration
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        // Check if user exists
        const [existing] = await db.execute(
            'SELECT id FROM users WHERE email = ? OR username = ?',
            [email, username]
        );
        
        if (existing.length > 0) {
            return res.status(400).json({ error: 'User already exists' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Insert user
        const [result] = await db.execute(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            [username, email, hashedPassword]
        );
        
        // Generate JWT
        const token = jwt.sign(
            { id: result.insertId, username, email },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '24h' }
        );
        
        res.json({
            success: true,
            token,
            user: { id: result.insertId, username, email }
        });
        
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// User Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Get user
        const [users] = await db.execute(
            'SELECT id, username, email, password FROM users WHERE email = ?',
            [email]
        );
        
        if (users.length === 0) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        
        const user = users[0];
        
        // Check password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        
        // Generate JWT
        const token = jwt.sign(
            { id: user.id, username: user.username, email: user.email },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '24h' }
        );
        
        res.json({
            success: true,
            token,
            user: { id: user.id, username: user.username, email: user.email }
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Get All Products
app.get('/api/products', async (req, res) => {
    try {
        const { search, category } = req.query;
        let query = `
            SELECT p.*, u.username as seller_username 
            FROM products p 
            JOIN users u ON p.seller_id = u.id 
            WHERE 1=1
        `;
        let params = [];
        
        if (search) {
            query += ' AND (p.title LIKE ? OR p.description LIKE ?)';
            params.push(`%${search}%`, `%${search}%`);
        }
        
        if (category) {
            query += ' AND p.category = ?';
            params.push(category);
        }
        
        query += ' ORDER BY p.created_at DESC';
        
        const [products] = await db.execute(query, params);
        res.json(products);
        
    } catch (error) {
        console.error('Get products error:', error);
        res.status(500).json({ error: 'Failed to fetch products' });
    }
});

// Get Single Product
app.get('/api/products/:id', async (req, res) => {
    try {
        const [products] = await db.execute(
            `SELECT p.*, u.username as seller_username 
             FROM products p 
             JOIN users u ON p.seller_id = u.id 
             WHERE p.id = ?`,
            [req.params.id]
        );
        
        if (products.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }
        
        res.json(products[0]);
        
    } catch (error) {
        console.error('Get product error:', error);
        res.status(500).json({ error: 'Failed to fetch product' });
    }
});

// Create Product with Image Upload (Protected)
app.post('/api/products', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        const { title, description, category, price } = req.body;
        const sellerId = req.user.id;
        
        // Use uploaded image path or fallback to emoji
        let imagePath;
        if (req.file) {
            imagePath = `/uploads/${req.file.filename}`;
        } else {
            // Fallback to emoji if no image uploaded
            const categoryEmojis = {
                'Electronics': '📱', 'Clothing': '👕', 'Home & Garden': '🏡',
                'Books': '📖', 'Sports': '⚽', 'Toys': '🧸', 'Other': '📦'
            };
            imagePath = categoryEmojis[category] || '📦';
        }
        
        const [result] = await db.execute(
            'INSERT INTO products (title, description, category, price, seller_id, image) VALUES (?, ?, ?, ?, ?, ?)',
            [title, description, category, price, sellerId, imagePath]
        );
        
        res.json({
            success: true,
            product: {
                id: result.insertId,
                title, description, category, price,
                seller_id: sellerId,
                image: imagePath
            }
        });
        
    } catch (error) {
        console.error('Create product error:', error);
        res.status(500).json({ error: 'Failed to create product' });
    }
});

// Update Product with optional Image Upload (Protected)
app.put('/api/products/:id', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        const { title, description, category, price } = req.body;
        const productId = req.params.id;
        const userId = req.user.id;
        
        // Check if user owns the product
        const [products] = await db.execute(
            'SELECT seller_id, image FROM products WHERE id = ?',
            [productId]
        );
        
        if (products.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }
        
        if (products[0].seller_id !== userId) {
            return res.status(403).json({ error: 'Not authorized' });
        }
        
        let imagePath = products[0].image; // Keep existing image by default
        
        if (req.file) {
            // Delete old image file if it exists and is not an emoji
            const oldImage = products[0].image;
            if (oldImage && oldImage.startsWith('/uploads/')) {
                const oldImagePath = path.join(__dirname, 'public', oldImage);
                if (fs.existsSync(oldImagePath)) {
                    fs.unlinkSync(oldImagePath);
                }
            }
            
            imagePath = `/uploads/${req.file.filename}`;
        } else if (!imagePath || imagePath.length === 1) {
            // If no current image or just emoji, set category emoji
            const categoryEmojis = {
                'Electronics': '📱', 'Clothing': '👕', 'Home & Garden': '🏡',
                'Books': '📖', 'Sports': '⚽', 'Toys': '🧸', 'Other': '📦'
            };
            imagePath = categoryEmojis[category] || '📦';
        }
        
        await db.execute(
            'UPDATE products SET title = ?, description = ?, category = ?, price = ?, image = ? WHERE id = ?',
            [title, description, category, price, imagePath, productId]
        );
        
        res.json({ success: true });
        
    } catch (error) {
        console.error('Update product error:', error);
        res.status(500).json({ error: 'Failed to update product' });
    }
});

// Delete Product (Protected)
app.delete('/api/products/:id', authenticateToken, async (req, res) => {
    try {
        const productId = req.params.id;
        const userId = req.user.id;
        
        // Check if user owns the product
        const [products] = await db.execute(
            'SELECT seller_id, image FROM products WHERE id = ?',
            [productId]
        );
        
        if (products.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }
        
        if (products[0].seller_id !== userId) {
            return res.status(403).json({ error: 'Not authorized' });
        }
        
        // Delete image file if it exists
        const imagePath = products[0].image;
        if (imagePath && imagePath.startsWith('/uploads/')) {
            const fullImagePath = path.join(__dirname, 'public', imagePath);
            if (fs.existsSync(fullImagePath)) {
                fs.unlinkSync(fullImagePath);
            }
        }
        
        await db.execute('DELETE FROM products WHERE id = ?', [productId]);
        res.json({ success: true });
        
    } catch (error) {
        console.error('Delete product error:', error);
        res.status(500).json({ error: 'Failed to delete product' });
    }
});

// Get User's Products (Protected)
app.get('/api/my-products', authenticateToken, async (req, res) => {
    try {
        const [products] = await db.execute(
            'SELECT * FROM products WHERE seller_id = ? ORDER BY created_at DESC',
            [req.user.id]
        );
        
        res.json(products);
        
    } catch (error) {
        console.error('Get user products error:', error);
        res.status(500).json({ error: 'Failed to fetch products' });
    }
});

// Cart Operations (Protected)
app.get('/api/cart', authenticateToken, async (req, res) => {
    try {
        const [cartItems] = await db.execute(
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

app.post('/api/cart', authenticateToken, async (req, res) => {
    try {
        const { productId, quantity = 1 } = req.body;
        const userId = req.user.id;
        
        // Check if item already in cart
        const [existing] = await db.execute(
            'SELECT id, quantity FROM cart WHERE user_id = ? AND product_id = ?',
            [userId, productId]
        );
        
        if (existing.length > 0) {
            // Update quantity
            await db.execute(
                'UPDATE cart SET quantity = quantity + ? WHERE user_id = ? AND product_id = ?',
                [quantity, userId, productId]
            );
        } else {
            // Add new item
            await db.execute(
                'INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, ?)',
                [userId, productId, quantity]
            );
        }
        
        res.json({ success: true });
        
    } catch (error) {
        console.error('Add to cart error:', error);
        res.status(500).json({ error: 'Failed to add to cart' });
    }
});

app.delete('/api/cart/:productId', authenticateToken, async (req, res) => {
    try {
        await db.execute(
            'DELETE FROM cart WHERE user_id = ? AND product_id = ?',
            [req.user.id, req.params.productId]
        );
        
        res.json({ success: true });
        
    } catch (error) {
        console.error('Remove from cart error:', error);
        res.status(500).json({ error: 'Failed to remove from cart' });
    }
});

// Checkout (Protected)
app.post('/api/checkout', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        
        // Get cart items
        const [cartItems] = await db.execute(
            `SELECT c.*, p.price 
             FROM cart c 
             JOIN products p ON c.product_id = p.id 
             WHERE c.user_id = ?`,
            [userId]
        );
        
        if (cartItems.length === 0) {
            return res.status(400).json({ error: 'Cart is empty' });
        }
        
        // Calculate total
        const total = cartItems.reduce((sum, item) => sum + (item.price * item.quantity), 0);
        
        // Create order
        const [orderResult] = await db.execute(
            'INSERT INTO orders (user_id, total) VALUES (?, ?)',
            [userId, total]
        );
        
        const orderId = orderResult.insertId;
        
        // Create order items
        for (const item of cartItems) {
            await db.execute(
                'INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)',
                [orderId, item.product_id, item.quantity, item.price]
            );
        }
        
        // Clear cart
        await db.execute('DELETE FROM cart WHERE user_id = ?', [userId]);
        
        res.json({ success: true, orderId });
        
    } catch (error) {
        console.error('Checkout error:', error);
        res.status(500).json({ error: 'Checkout failed' });
    }
});

// Get Purchase History (Protected)
app.get('/api/orders', authenticateToken, async (req, res) => {
    try {
        const [orders] = await db.execute(
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

// Update Profile (Protected)
app.put('/api/profile', authenticateToken, async (req, res) => {
    try {
        const { username, email } = req.body;
        const userId = req.user.id;
        
        // Check if username/email already exists (excluding current user)
        const [existing] = await db.execute(
            'SELECT id FROM users WHERE (username = ? OR email = ?) AND id != ?',
            [username, email, userId]
        );
        
        if (existing.length > 0) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }
        
        await db.execute(
            'UPDATE users SET username = ?, email = ? WHERE id = ?',
            [username, email, userId]
        );
        
        res.json({ success: true });
        
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

// Start server
connectDB().then(() => {
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
});