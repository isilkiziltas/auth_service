const express = require('express');

app.use(express.json()); // JSON isteğini parse etmek için gerekli

app.post('/signup', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    res.status(201).json({ message: 'User registered successfully!' });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();
const PORT = 3000;

// Kullanıcı verilerini tutmak için geçici bir in-memory veri yapısı
const users = {};

// JWT için gizli anahtar
const SECRET_KEY = 'supersecretkey';
const RESET_TOKEN_KEY = 'resetsecretkey';

// Middleware - JSON gövdeyi ayrıştır
app.use((req, res, next) => {
    const originalUrl = req.originalUrl;
    const cleanUrl = stripUrlAuth(originalUrl, `http://localhost:${PORT}`);
    console.log(`Request received at: ${cleanUrl || 'Invalid URL'}`);
    next();
});

// URL'deki kimlik bilgilerini temizleyen bir fonksiyon
function stripUrlAuth(url, baseUrl = "http://localhost:3000") {
    try {
        const fullUrl = new URL(url, baseUrl); // Base URL ile tam URL oluştur
        fullUrl.username = '';
        fullUrl.password = '';
        return fullUrl.toString();
    } catch (error) {
        console.error('Invalid URL:', error.message);
        return null;
    }
}

// Middleware - Gelen istekte URL'yi temizler ve loglar
app.use((req, res, next) => {
    const originalUrl = req.originalUrl;
    const cleanUrl = stripUrlAuth(originalUrl);
    console.log(`Request received at: ${cleanUrl || 'Invalid URL'}`);
    next();
});

// Middleware - Token doğrulama
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer token formatı
    if (!token) return res.status(401).json({ message: 'Access Denied: No Token Provided' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid Token' });
        req.user = user;
        next();
    });
};

// Kayıt Ol
app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    if (users[username]) {
        return res.status(409).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    users[username] = { password: hashedPassword };
    res.status(201).json({ message: 'User registered successfully' });
});

// Giriş Yap
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    const user = users[username];
    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
    res.status(200).json({ message: 'Login successful', token });
});

// Çıkış Yap
app.delete('/logout', (req, res) => {
    res.status(200).json({ message: 'Logged out successfully' });
});

// Özel Rota
app.get('/private_route', authenticateToken, (req, res) => {
    res.status(200).json({ message: `Welcome ${req.user.username}, you have access to this route!` });
});

// Şifre Sıfırlama İsteği
app.post('/forgot_password', (req, res) => {
    const { username } = req.body;
    if (!username || !users[username]) {
        return res.status(404).json({ message: 'User not found' });
    }

    const resetToken = jwt.sign({ username }, RESET_TOKEN_KEY, { expiresIn: '15m' });
    // Gerçek bir uygulamada bu token bir e-posta ile gönderilir.
    res.status(200).json({ message: 'Password reset token generated', resetToken });
});

// Şifre Sıfırla
app.post('/reset_password', async (req, res) => {
    const { resetToken, newPassword } = req.body;
    if (!resetToken || !newPassword) {
        return res.status(400).json({ message: 'Reset token and new password are required' });
    }

    jwt.verify(resetToken, RESET_TOKEN_KEY, async (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid or expired reset token' });

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        users[user.username].password = hashedPassword;
        res.status(200).json({ message: 'Password reset successful' });
    });
});

// Sunucu Başlat
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});