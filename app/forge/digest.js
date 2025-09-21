const fs = require('fs');
const crypto = require('crypto');

const filePath = 'test.txt'; // vagy bármilyen másik fájl

const data = fs.readFileSync(filePath);

// SHA256 digest
const hash = crypto.createHash('sha256');
hash.update(data);
const digestHex = hash.digest('hex');

// Méret
const fileSize = data.length;

console.log(`Fájl: ${filePath}`);
console.log(`Méret: ${fileSize} byte`);
console.log(`SHA256 digest: ${digestHex}`);
