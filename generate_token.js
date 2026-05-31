const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const keysDir = path.join(__dirname, 'keys');
const privateKeyPath = path.join(keysDir, 'private.pem');

if (!fs.existsSync(privateKeyPath)) {
  console.error("❌ Error: private.pem not found. Please run generate_keys.sh first.");
  process.exit(1);
}

const privateKey = fs.readFileSync(privateKeyPath, 'utf8');

// Helper to write file safely
const saveToken = (filename, token) => {
  fs.writeFileSync(path.join(keysDir, filename), token);
};

// 1. Generate VALID Token (Expires in 5 minutes)
const validToken = jwt.sign(
  {
    sub: 'alice.security@company.com',
    role: 'finance-manager',
    clearance: 'SECRET',
    iss: 'zta-pdp',
    aud: 'zta-pep'
  },
  privateKey,
  {
    algorithm: 'RS256',
    expiresIn: '5m'
  }
);
saveToken('valid_token.txt', validToken);

// 2. Generate EXPIRED Token (Expired 5 minutes ago)
const expiredToken = jwt.sign(
  {
    sub: 'bob.developer@company.com',
    role: 'engineer',
    clearance: 'PUBLIC',
    iss: 'zta-pdp',
    aud: 'zta-pep'
  },
  privateKey,
  {
    algorithm: 'RS256',
    expiresIn: '-5m' // Set expiration to past
  }
);
saveToken('expired_token.txt', expiredToken);

// 3. Generate FORGED Token (Signed with a rogue/fake RSA key)
// This simulates a hacker creating their own keypair and trying to sign a payload pretending to be Admin
console.log("Generating rogue key pair for simulating a forged signature attack...");
const { privateKey: roguePrivateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

const forgedToken = jwt.sign(
  {
    sub: 'hacker@attacker.com',
    role: 'administrator', // Claiming admin access!
    clearance: 'TOP_SECRET',
    iss: 'zta-pdp',
    aud: 'zta-pep'
  },
  roguePrivateKey, // SIGNED WITH A FAKE PRIVATE KEY!
  {
    algorithm: 'RS256',
    expiresIn: '1h'
  }
);
saveToken('forged_token.txt', forgedToken);

console.log('\n================================================================');
console.log('🔑 ZERO TRUST ARCHITECTURE TOKEN GENERATOR');
console.log('================================================================');
console.log('\n✅ [1/3] VALID JWT (Expires in 5m) -> saved to keys/valid_token.txt:');
console.log(validToken.substring(0, 40) + '...' + validToken.substring(validToken.length - 20));

console.log('\n❌ [2/3] EXPIRED JWT -> saved to keys/expired_token.txt:');
console.log(expiredToken.substring(0, 40) + '...' + expiredToken.substring(expiredToken.length - 20));

console.log('\n🛡️ [3/3] FORGED JWT (Signed with fake key) -> saved to keys/forged_token.txt:');
console.log(forgedToken.substring(0, 40) + '...' + forgedToken.substring(forgedToken.length - 20));
console.log('================================================================\n');
