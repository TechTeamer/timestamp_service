const forge = require('node-forge');
const fs = require('fs');

// Kulcs + tanúsítvány generálása
function generateKeyAndCert() {
  return new Promise((resolve, reject) => {
    forge.pki.rsa.generateKeyPair({ bits: 2048, workers: 2 }, (err, keypair) => {
      if (err) return reject(err);

      const cert = forge.pki.createCertificate();
      cert.publicKey = keypair.publicKey;
      cert.serialNumber = (Math.floor(Math.random() * 1e9)).toString();
      const now = new Date();
      cert.validity.notBefore = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      cert.validity.notAfter = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);

      const attrs = [{ name: 'commonName', value: 'Mock TSA' }];
      cert.setSubject(attrs);
      cert.setIssuer(attrs);

      cert.setExtensions([
        { name: 'basicConstraints', cA: false, critical: true },
        { name: 'keyUsage', digitalSignature: true, nonRepudiation: true },
        {
          name: 'extKeyUsage',
          timeStamping: true, // <- fontos!
          critical: true,
        },
        { name: 'subjectKeyIdentifier' }
      ]);

      cert.sign(keypair.privateKey, forge.md.sha256.create());

      resolve({ keypair, cert });
    });
  });
}

// Mock TSR (egyszerű JSON base64 aláírással)
function createMockTSR(cert, privateKey, dataBytes) {
  const md = forge.md.sha256.create();
  md.update(dataBytes.toString('binary'));

  const signature = privateKey.sign(md);

  const mockTSR = {
    cert: forge.pki.certificateToPem(cert),
    signature: forge.util.encode64(signature),
  };

  return Buffer.from(JSON.stringify(mockTSR));
}

async function main() {
  if (process.argv.length < 3) {
    console.log('Usage: node tsa_mock.js <file_to_timestamp>');
    process.exit(1);
  }

  const inputFile = process.argv[2];
  const dataBytes = fs.readFileSync(inputFile);

  const { keypair, cert } = await generateKeyAndCert();

  // Mentés PEM fájlokba
  const certPem = forge.pki.certificateToPem(cert);
  const keyPem = forge.pki.privateKeyToPem(keypair.privateKey);

  fs.writeFileSync('tsa.crt.pem', certPem);
  fs.writeFileSync('tsa.key.pem', keyPem);

  console.log('\n=== Tanúsítvány (tsa.crt.pem) ===\n');
  console.log(certPem);

  console.log('\n=== Privát kulcs (tsa.key.pem) ===\n');
  console.log(keyPem);

  // Mock TSR létrehozása
  const tsr = createMockTSR(cert, keypair.privateKey, dataBytes);
  fs.writeFileSync('response.tsr', tsr);

  console.log('\n✅ Mock timestamp response elmentve: response.tsr');
}

main().catch(console.error);
