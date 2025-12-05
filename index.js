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
