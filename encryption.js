const crypto = require('crypto');

// Function to encrypt a password using Node.js crypto module
function encryptPassword(password) {
  const algorithm = 'aes-256-gcm';
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encryptedPassword = cipher.update(password, 'utf8', 'hex');
  encryptedPassword += cipher.final('hex');

  const authTag = cipher.getAuthTag();

  return {
    encryptedPassword,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
    key: key.toString('hex')
  };
}

// Function to decrypt an encrypted password using Node.js crypto module
function decryptPassword(encryptedData) {
  const algorithm = 'aes-256-gcm';

  const decipher = crypto.createDecipheriv(algorithm, Buffer.from(encryptedData.key, 'hex'), Buffer.from(encryptedData.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));

  let decryptedPassword = decipher.update(encryptedData.encryptedPassword, 'hex', 'utf8');
  decryptedPassword += decipher.final('utf8');

  return decryptedPassword;
}

// Example usage
const password = 'sidneydodd65';
const encryptedData = encryptPassword(password);

console.log('Encrypted Password:', encryptedData.encryptedPassword);

const decryptedPassword = decryptPassword(encryptedData);
console.log('Decrypted Password:', decryptedPassword);
