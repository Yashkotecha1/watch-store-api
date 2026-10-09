const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const db = require('./db');
const { authenticate, requireAdmin } = require('./middleware/auth');
const upload = require('./middleware/upload');

const app = express();
app.use(cors());
app.use(express.json());

// Serve static images directly from browser: http://localhost:5000/uploads/filename.jpg
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ==========================================
// 1. AUTHENTICATION (REGISTER & LOGIN)
// ==========================================

app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, role } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        const [existing] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
        if (existing.length > 0) {
            return res.status(409).json({ error: 'Email already registered' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const userRole = role === 'admin' ? 'admin' : 'customer';

        const [result] = await db.query(
            'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
            [name, email, hashedPassword, userRole]
        );

        res.status(201).json({ message: 'User registered successfully', userId: result.insertId });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const [users] = await db.query('SELECT * FROM users WHERE email = ?', [email]);

        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const user = users[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            message: 'Login successful',
            token,
            user: { id: user.id, name: user.name, email: user.email, role: user.role }
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==========================================
// 2. ADMIN DASHBOARD
// ==========================================

app.get('/api/dashboard', authenticate, requireAdmin, async (req, res) => {
    try {
        const [[sales]] = await db.query('SELECT COALESCE(SUM(total_amount), 0) AS totalRevenue FROM orders');
        const [[orders]] = await db.query('SELECT COUNT(*) AS totalOrders FROM orders');
        const [[watches]] = await db.query('SELECT COUNT(*) AS totalWatches FROM products');
        const [[lowStock]] = await db.query('SELECT COUNT(*) AS lowStockCount FROM products WHERE stock < 5');

        res.json({
            totalRevenue: sales.totalRevenue,
            totalOrders: orders.totalOrders,
            totalWatches: watches.totalWatches,
            lowStockAlerts: lowStock.lowStockCount
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==========================================
// 3. CATEGORIES (WITH IMAGE UPLOAD)
// ==========================================

app.get('/api/categories', async (req, res) => {
    try {
        const [rows] = await db.query('SELECT * FROM categories');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/categories', authenticate, requireAdmin, upload.single('image'), async (req, res) => {
    try {
        const { name, description } = req.body;
        const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;

        const [result] = await db.query(
            'INSERT INTO categories (name, description, image_url) VALUES (?, ?, ?)',
            [name, description, imageUrl]
        );

        res.status(201).json({ id: result.insertId, name, description, image_url: imageUrl });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==========================================
// 4. WATCH PRODUCTS (WITH IMAGE UPLOAD)
// ==========================================

app.get('/api/products', async (req, res) => {
    try {
        const [rows] = await db.query(`
            SELECT p.*, c.name AS category_name 
            FROM products p 
            LEFT JOIN categories c ON p.category_id = c.id
        `);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/products', authenticate, requireAdmin, upload.single('image'), async (req, res) => {
    try {
        const { category_id, name, brand, price, stock, description } = req.body;
        const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;

        const [result] = await db.query(
            'INSERT INTO products (category_id, name, brand, price, stock, description, image_url) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [category_id, name, brand, price, stock, description, imageUrl]
        );

        res.status(201).json({
            id: result.insertId,
            name,
            brand,
            price,
            stock,
            image_url: imageUrl
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==========================================
// 5. CART (BOUND TO LOGGED-IN CUSTOMER)
// ==========================================

app.get('/api/cart', authenticate, async (req, res) => {
    try {
        const [cart] = await db.query(`
            SELECT c.id AS cart_item_id, c.quantity, p.id AS product_id, p.name, p.brand, p.price, p.image_url, p.stock
            FROM cart_items c
            JOIN products p ON c.product_id = p.id
            WHERE c.user_id = ?
        `, [req.user.id]);
        res.json(cart);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/cart', authenticate, async (req, res) => {
    try {
        const { product_id, quantity } = req.body;
        const qty = quantity || 1;

        await db.query(`
            INSERT INTO cart_items (user_id, product_id, quantity)
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE quantity = quantity + VALUES(quantity)
        `, [req.user.id, product_id, qty]);

        res.json({ message: 'Watch added to cart' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==========================================
// 6. CHECKOUT (TRANSACTIONAL)
// ==========================================

app.post('/api/checkout', authenticate, async (req, res) => {
    const { shipping_address } = req.body;
    if (!shipping_address) {
        return res.status(400).json({ error: 'Shipping address is required' });
    }

    const conn = await db.getConnection();
    try {
        await conn.beginTransaction();

        const [cart] = await conn.query(`
            SELECT c.product_id, c.quantity, p.price, p.stock, p.name 
            FROM cart_items c 
            JOIN products p ON c.product_id = p.id 
            WHERE c.user_id = ?
        `, [req.user.id]);

        if (cart.length === 0) {
            throw new Error('Your cart is empty');
        }

        let totalAmount = 0;
        for (const item of cart) {
            if (item.stock < item.quantity) {
                throw new Error(`Insufficient stock for watch: ${item.name}`);
            }
            totalAmount += item.price * item.quantity;
        }

        const [orderResult] = await conn.query(
            'INSERT INTO orders (user_id, total_amount, shipping_address, status) VALUES (?, ?, ?, "pending")',
            [req.user.id, totalAmount, shipping_address]
        );
        const orderId = orderResult.insertId;

        for (const item of cart) {
            await conn.query(
                'INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)',
                [orderId, item.product_id, item.quantity, item.price]
            );

            await conn.query(
                'UPDATE products SET stock = stock - ? WHERE id = ?',
                [item.quantity, item.product_id]
            );
        }

        await conn.query('DELETE FROM cart_items WHERE user_id = ?', [req.user.id]);

        await conn.commit();
        res.status(201).json({ message: 'Order placed successfully', orderId, totalAmount });
    } catch (err) {
        await conn.rollback();
        res.status(400).json({ error: err.message });
    } finally {
        conn.release();
    }
});

// ==========================================
// 7. ORDER HISTORY
// ==========================================

app.get('/api/orders/history', authenticate, async (req, res) => {
    try {
        const [orders] = await db.query(
            'SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC',
            [req.user.id]
        );

        for (let order of orders) {
            const [items] = await db.query(`
                SELECT oi.quantity, oi.price, p.name, p.brand, p.image_url
                FROM order_items oi
                JOIN products p ON oi.product_id = p.id
                WHERE oi.order_id = ?
            `, [order.id]);
            order.items = items;
        }

        res.json(orders);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==========================================
// 8. DELIVERY STATUS UPDATE (ADMIN)
// ==========================================

app.patch('/api/orders/:id/status', authenticate, requireAdmin, async (req, res) => {
    try {
        const { status } = req.body;
        const validStatuses = ['pending', 'confirmed', 'shipped', 'out_for_delivery', 'delivered', 'cancelled'];

        if (!validStatuses.includes(status)) {
            return res.status(400).json({ error: 'Invalid delivery status' });
        }

        const [result] = await db.query('UPDATE orders SET status = ? WHERE id = ?', [status, req.params.id]);

        if (result.matchedRows === 0) {
            return res.status(404).json({ error: 'Order not found' });
        }

        res.json({ message: `Order #${req.params.id} updated to ${status}` });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});