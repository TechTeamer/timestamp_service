const fs = require('fs');
const forge = require('node-forge');
const asn1 = forge.asn1;

// --- ADATOK --- //

const sha256OID = '2.16.840.1.101.3.4.2.1'; // SHA-256 OID
const digestHex = 'ca447095370ccb6f66157119a7dd100ee889a7c6baf69a52b37d0c4040c19e68'; // példa digest
const digestBytes = forge.util.hexToBytes(digestHex);

// --- MESSAGE IMPRINT (ASN.1) --- //
const messageImprint = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
  // hashAlgorithm SEQUENCE
  asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    // algorithm OID
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(sha256OID).getBytes()),
    // parameters NULL
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, ''),
  ]),
  // hashedMessage OCTET STRING
  asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, digestBytes),
]);

// --- TSTInfo (ASN.1) --- //
const tstInfo = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
  // version INTEGER (1)
  asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, String.fromCharCode(1)),
  // policy OBJECT IDENTIFIER (példa OID)
  asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer('1.2.3.4.1').getBytes()),
  // messageImprint (az előző)
  messageImprint,
  // serialNumber INTEGER (1)
  asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, String.fromCharCode(1)),
  // genTime GeneralizedTime (most)
  asn1.create(asn1.Class.UNIVERSAL, asn1.Type.GENERALIZEDTIME, false, toGeneralizedTime(new Date())),
]);

// DER kódolás
const tstInfoDer = asn1.toDer(tstInfo).getBytes();

// --- SIGNED DATA (PKCS7) --- //

const privateKeyPem = fs.readFileSync('./tsa.key.pem', 'utf8');
const certPem = fs.readFileSync('./tsa.crt.pem', 'utf8');

const p7 = forge.pkcs7.createSignedData();

// A TSTInfo DER bufferét kell tartalomként adni, az ASN.1 Bufferből forge Buffer kell
p7.content = forge.util.createBuffer(tstInfoDer);

p7.addCertificate(certPem);
p7.addSigner({
  key: forge.pki.privateKeyFromPem(privateKeyPem),
  certificate: forge.pki.certificateFromPem(certPem),
  digestAlgorithm: forge.pki.oids.sha256,
  authenticatedAttributes: [
    {
      type: forge.pki.oids.contentType,
      // id-ct-TSTInfo OID, string formában
      value: '1.2.840.113549.1.9.16.1.4',
    },
    {
      type: forge.pki.oids.messageDigest,
      value: forge.md.sha256.create().update(tstInfoDer).digest().getBytes(),
    },
    {
      type: forge.pki.oids.signingTime,
      value: new Date(),
    },
  ],
});
p7.sign();

// PKIStatusInfo ASN.1 objektum (status = 0)
const status = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
  asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, String.fromCharCode(0)), // status = granted
  // opcionális mezők: statusString, failInfo itt kihagyva
]);

// TimeStampToken (PKCS7) ASN.1 objektum
const timeStampTokenAsn1 = p7.toAsn1();

// TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken TimeStampToken }
const tsResp = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
  status,
  timeStampTokenAsn1,
]);

// DER kódolás és fájlba írás
const tsRespDerBytes = asn1.toDer(tsResp).getBytes();
fs.writeFileSync('mock_response.tsr', Buffer.from(tsRespDerBytes, 'binary'));

console.log('✅ mock_response.tsr elkészült!');

function toGeneralizedTime(date) {
  function pad(n) { return n < 10 ? '0' + n : n; }
  return date.getUTCFullYear().toString() +
    pad(date.getUTCMonth() + 1) +
    pad(date.getUTCDate()) +
    pad(date.getUTCHours()) +
    pad(date.getUTCMinutes()) +
    pad(date.getUTCSeconds()) +
    'Z';
}
