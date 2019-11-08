# eff-pre
An efficient Proxy Re-encryption library in JavaScript without pairing.

It supports encrypt, decrypt, rekeyGen, reEnc, sign and verify.
> It's an implement of paper `Efficient Unidirectional Proxy Re-encryption`

> Currently using curve SECP256K1 as default curve.

## Usage
Using high level function in class `PREClient` and `PREProxy`.
```javascript
const {PRE, PREClient, PREProxy} = require("eff-pre");
const crypto = require("crypto");

const L0 = 32; // longest byte size can be encrypted
const L1 = 16; // customized length
PRE.init(L0, L1, PRE.CURVE.SECP256K1).then(() => {
  const A = new PREClient();
  const B = new PREClient();
  const C = new PREClient();
  // the message to be encrypted
  // it should be no longer than L0, usually AES key
  const M = crypto.randomBytes(L0);
  A.keyGen();
  B.keyGen();
  C.keyGen();
  const pkA = A.getPk();
  const pkB = B.getPk();

  // test A encrypt and decrypt on his own
  const c1 = A.enc(M, {transformable: true});
  const [valid1, d1] = A.dec(c1);
  console.log("A Dec [transformable]:", valid1, "Same:", d1.equals(M));

  // test A shares c1 to B with P, so that B can decrypt
  // usecase: A want to share already encrypted information with B
  //          without download, decrypt, encrypt with B's pk and send to B
  //          by send reKey to proxy P, P will transfer the ciphertext so that B can decrypt.

  const reKeyA2B = A.reKeyGen(pkB);
  const [valid2, c2] = PREProxy.reEnc(c1, reKeyA2B, pkA);
  console.log("ReEnc:", valid2);
  const [valid3, d2] = B.dec(c2);
  console.log("B Dec:", valid3, "Same:", d2.equals(M));
  // C (others) cannot decrypt
  console.log("C Dec:", C.dec(c2)[0]);

  // sign and verify
  const sig = A.sign(M);
  const verified = PREClient.verify(M, sig, pkA);
  console.log("Signature verified", verified);

  // message that cannot be shared
  // usecase: A want to encrypt private information with no intention of sharing
  const c3 = A.enc(M, {transformable: false});
  const [valid4, d3] = A.dec(c3);
  console.log("A Dec [non-transformable]:", valid4, "Same:", d3.equals(M));
  const [valid5, c4] = PREProxy.reEnc(c3, reKeyA2B, pkA);
  console.log("ReEnc:", valid5); // cannot reEnc non-transformable ciphertext

}).catch(r => {
  console.log(r)
});
```

## Reference
Chow, Sherman SM, et al. "Efficient unidirectional proxy re-encryption." International Conference on Cryptology in Africa. Springer, Berlin, Heidelberg, 2010.