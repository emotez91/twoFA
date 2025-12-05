const express = require('express');
const bodyParser = require('body-parser');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const admin = require('firebase-admin');

// 1. Initialize Firestore
// (Cloud Run automatically handles credentials here)
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

// NEW: Endpoint to check Factor 1 (Password)
app.post('/login', async (req, res) => {
    try {
        const { userId, password } = req.body;
        if (!userId || !password) return res.status(400).json({ error: "Missing userId or password" });

        // 1. REALITY CHECK: Replace this with your actual DB password check
        // For now, we accept ANY password just to test the flow
        const isPasswordCorrect = true;

        if (!isPasswordCorrect) {
            return res.status(401).json({ error: "Invalid password" });
        }

        // 2. Check if this user has 2FA enabled in Firestore
        const userDoc = await db.collection('users').doc(userId).get();
        const userData = userDoc.exists ? userDoc.data() : {};

        if (userData.two_fa_enabled) {
            // CASE A: Password Good, but 2FA is ON.
            // Tell the app to ask for the code.
            return res.json({
                status: "2FA_REQUIRED",
                message: "Please enter your 6-digit code"
            });
        } else {
            // CASE B: Password Good, 2FA is OFF.
            // Login complete! Issue the token immediately.
            const sessionToken = jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: '1h' });
            return res.json({
                status: "SUCCESS",
                token: sessionToken
            });
        }
    } catch (err) {
        console.error('Error in /login:', err);
        return res.status(500).json({ error: "Internal server error" });
    }
});

app.post('/setup-2fa', async (req, res) => {
    const userId = req.body.userId;
    if(!userId) return res.status(400).send("Missing userId");

    const secret = speakeasy.generateSecret({ name: "MyApp (" + userId + ")" });
    const encryptedSecret = encrypt(secret.base32);

    // 2. SAVE TO DATABASE (Persistent!)
    await db.collection('users').doc(userId).set({
        two_fa_secret: encryptedSecret,
        two_fa_enabled: false
    }, { merge: true });

    qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
        res.json({ qr_code: data_url, manual_entry: secret.base32 });
    });
});

app.post('/verify-2fa', async (req, res) => {
    const { userId, token } = req.body;
    
    // 3. GET FROM DATABASE
    const userDoc = await db.collection('users').doc(userId).get();

    if (!userDoc.exists) return res.status(404).json({ error: "User not found" });

    const userData = userDoc.data();
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
