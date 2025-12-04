const express = require('express');
const bodyParser = require('body-parser');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Forcing a new build

const app = express();
app.use(bodyParser.json());

// --- SECURITY HELPERS ---

// 1. Helper to Encrypt the 2FA Secret before storing in DB
// Uses your 'TWO_FACTOR_ENCRYPTION_KEY' from Cloud Run
function encrypt(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(process.env.TWO_FACTOR_ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

// 2. Helper to Decrypt the 2FA Secret when verifying
function decrypt(text) {
    let textParts = text.split(':');
    let iv = Buffer.from(textParts.shift(), 'hex');
    let encryptedText = Buffer.from(textParts.join(':'), 'hex');
    let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(process.env.TWO_FACTOR_ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

// --- MOCK DATABASE (Replace this with your real DB code) ---
// We are simulating a DB here to make this code copy-paste runnable.
const usersDB = {}; 

// --- ENDPOINTS ---

// STEP 1: Setup 2FA (User scans the QR code)
app.post('/setup-2fa', (req, res) => {
    const userId = req.body.userId; // In real app, get this from session
    
    // Generate a temporary secret
    const secret = speakeasy.generateSecret({ name: "MyApp (" + userId + ")" });
    
    // Encrypt it using your Cloud Run Env Variable
    const encryptedSecret = encrypt(secret.base32);
    
    // Store in DB (Mocking this part)
    usersDB[userId] = { 
        two_fa_secret: encryptedSecret, 
        two_fa_enabled: false 
    };

    // Generate QR Code for frontend to display
    qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
        res.json({ qr_code: data_url, manual_entry: secret.base32 });
    });
});

// STEP 2: Verify & Login (User enters the 6-digit code)
app.post('/verify-2fa', (req, res) => {
    const { userId, token } = req.body;
    const user = usersDB[userId];

    if (!user) return res.status(404).json({ error: "User not found" });

    // Decrypt the stored secret
    const decryptedSecret = decrypt(user.two_fa_secret);

    // Verify the code
    const verified = speakeasy.totp.verify({
        secret: decryptedSecret,
        encoding: 'base32',
        token: token,
        window: 1 // Allows for slight time drift
    });

    if (verified) {
        // Code is good! Issue the JWT Session
        user.two_fa_enabled = true; // Mark as enabled
        
        // Sign token using your 'JWT_SECRET' from Cloud Run
        const sessionToken = jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: '1h' });
        
        res.json({ status: "SUCCESS", token: sessionToken });
    } else {
        res.status(401).json({ status: "FAILED", message: "Invalid code" });
    }
});

const port = process.env.PORT || 8080;
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
