const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Ideally, these should be stored in .env for security
const JWT_SECRET = 'your-jwt-secret-key';
const ENCRYPTION_KEY = crypto.randomBytes(32); // 32 bytes = 256 bits
const IV = crypto.randomBytes(16); // 16 bytes IV for AES

// 🔐 Encrypt a JWT payload
const encrypt = (payload) => {
  // Create JWT token
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

  // Encrypt the JWT token
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, IV);
  let encrypted = cipher.update(token, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Return both encrypted token and IV (needed for decryption)
  return {
    token: encrypted,
    iv: IV.toString('hex'), // send IV as hex string
  };
};

// 🔓 Decrypt the token and verify JWT
const decrypt = ({ token, iv }) => {
  try {
    const ivBuffer = Buffer.from(iv, 'hex');
    const decipher = crypto.createDecipheriv(
      'aes-256-cbc',
      ENCRYPTION_KEY,
      ivBuffer
    );
    let decrypted = decipher.update(token, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    // Verify and decode JWT
    const decoded = jwt.verify(decrypted, JWT_SECRET);
    return decoded;
  } catch (err) {
    console.error('❌ Decryption or verification failed:', err.message);
    return null;
  }
};

module.exports = {
  encrypt,
  decrypt,
};