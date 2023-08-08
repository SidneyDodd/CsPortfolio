const crypto = require('crypto');

// Function to generate a random salt
function generateSalt() {
  return crypto.randomBytes(16).toString('hex');
}

// Function to encrypt a password using Node.js crypto module
function encryptPassword(password) {
  const algorithm = 'aes-256-gcm';
  const salt = generateSalt();
  const key = crypto.scryptSync(password, salt, 32);
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encryptedPassword = cipher.update(password, 'utf8', 'hex');
  encryptedPassword += cipher.final('hex');

  const authTag = cipher.getAuthTag();

  return {
    encryptedPassword,
    salt,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
  };
}

// Function to decrypt an encrypted password using Node.js crypto module
function decryptPassword(encryptedData, password) {
  const algorithm = 'aes-256-gcm';

  const key = crypto.scryptSync(password, encryptedData.salt, 32)
  const decipher = crypto.createDecipheriv(algorithm, key, Buffer.from(encryptedData.iv, 'hex'), Buffer.from(encryptedData.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));

  let decryptedPassword = decipher.update(encryptedData.encryptedPassword, 'hex', 'utf8');
  decryptedPassword += decipher.final('utf8');

  return decryptedPassword;
}

// Example usage
const password = 'sidneydodd65';
const encryptedData = encryptPassword(password);

console.log('Encrypted Password:', encryptedData.encryptedPassword);

const decryptedPassword = decryptPassword(encryptedData, password);
console.log('Decrypted Password:', decryptedPassword);
