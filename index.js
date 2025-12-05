const express = require('express');
const bodyParser = require('body-parser');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const admin = require('firebase-admin');
const bcrypt = require('bcryptjs'); // NEW: Security Library

// Initialize Firestore
admin.initializeApp();
const db = admin.firestore();

const app = express();
app.use(bodyParser.json());

// --- HELPERS ---
function encrypt(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(process.env.TWO_FACTOR_ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    let textParts = text.split(':');
    let iv = Buffer.from(textParts.shift(), 'hex');
    let encryptedText = Buffer.from(textParts.join(':'), 'hex');
    let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(process.env.TWO_FACTOR_ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

// --- ENDPOINTS ---

// 1. SIGN UP (Create a new user)
app.post('/signup', async (req, res) => {
    const { userId, password } = req.body;
    
    if(!userId || !password) return res.status(400).send("Missing fields");

    // Check if user already exists
    const userDoc = await db.collection('users').doc(userId).get();
    if (userDoc.exists) return res.status(400).send("User already exists");

    // Hash the password (Security Best Practice)
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Save to Firestore
    await db.collection('users').doc(userId).set({
        password_hash: hashedPassword,
        two_fa_enabled: false,
        created_at: new Date()
    });

    res.json({ status: "SUCCESS", message: "User created" });
});

// 2. LOGIN (Factor 1 Check)
app.post('/login', async (req, res) => {
    const { userId, password } = req.body;

    // Get user from DB
    const userDoc = await db.collection('users').doc(userId).get();
    if (!userDoc.exists) return res.status(401).json({ error: "Invalid credentials" });

    const userData = userDoc.data();

    // Compare Password with Hash
    const validPass = await bcrypt.compare(password, userData.password_hash);
    if (!validPass) return res.status(401).json({ error: "Invalid credentials" });

    // Password is good! Check 2FA status.
    if (userData.two_fa_enabled) {
        return res.json({ status: "2FA_REQUIRED" });
    } else {
        const sessionToken = jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: '1h' });
        return res.json({ status: "SUCCESS", token: sessionToken });
    }
});

// 3. SETUP 2FA
app.post('/setup-2fa', async (req, res) => {
    const userId = req.body.userId; // In real app, extract this from a temporary session token
    
    const secret = speakeasy.generateSecret({ name: "MyApp (" + userId + ")" });
    const encryptedSecret = encrypt(secret.base32);

    await db.collection('users').doc(userId).update({
        two_fa_secret: encryptedSecret
    });

    qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
        res.json({ qr_code: data_url, manual_entry: secret.base32 });
    });
});

// 4. VERIFY 2FA (Factor 2 Check)
app.post('/verify-2fa', async (req, res) => {
    const { userId, token } = req.body;
    
    const userDoc = await db.collection('users').doc(userId).get();
    if (!userDoc.exists) return res.status(404).json({ error: "User not found" });

    const userData = userDoc.data();
    if (!userData.two_fa_secret) return res.status(400).json({ error: "2FA not set up" });

    const decryptedSecret = decrypt(userData.two_fa_secret);

    const verified = speakeasy.totp.verify({
        secret: decryptedSecret,
        encoding: 'base32',
        token: token,
        window: 1
    });

    if (verified) {
        await db.collection('users').doc(userId).update({ two_fa_enabled: true });
        const sessionToken = jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ status: "SUCCESS", token: sessionToken });
    } else {
        res.status(401).json({ status: "FAILED", message: "Invalid code" });
    }
});

const port = process.env.PORT || 8080;
app.listen(port, () => { console.log(`Server running on port ${port}`); });
