# eff-pre
An efficient Proxy Re-encryption library in JavaScript without pairing.
> It's an implement of paper `Efficient Unidirectional Proxy Re-encryption`

> Currently using curve BLS12-381 curve (G1) in `mcl-wasm` for speed.

## Usage
This library is static utility library, which can be used in the following class `PREClient` and `PREProxy`
```javascript
const PRE = require("eff-pre");
const crypto = require("crypto");

class PREClient {
    constructor(g, {sk = undefined} = {}) {
        this.g = g;
        this.pk = undefined;
        this.sk = undefined;
    }

    keyGen() {
        [this.sk, this.pk] = PRE.keyGen(this.g);
        return [this.sk, this.pk]
    }

    loadKey(sk) {
        this.sk = PRE.parseSk(sk);
        this.pk = PRE.pkFromSk(this.g, this.sk);

    }

    getSk() {
        return PRE.keyToBuf(this.sk)
    }

    getPk() {
        return PRE.keyToBuf(this.pk)
    }

    reKeyGen(to) {
        to = PRE.parsePk(to);
        return PRE.reKeyGen(this.g, this.sk, this.pk, to)

    }

    enc(M, {to = this.pk, transformable = true} = {}) {
        to = PRE.parsePk(to);
        if (transformable)
            return PRE.enc1(this.g, M, to);
        else
            return PRE.enc2(this.g, M, to);
    }

    dec(C) {
        return C.length === PRE.C1LEN ?
            PRE.dec1(this.g, C, this.sk, this.pk) :
            PRE.dec2(this.g, C, this.sk, this.pk)

    }


}

class PREProxy {
    constructor(g) {
        this.g = g;
    }

    reEnc(C1, reKey, owner) {
        owner = PRE.parsePk(owner);
        return PRE.reEnc(this.g, reKey, C1, owner)
    }
}

PRE.init().then(g => {
    const A = new PREClient(g);
    const B = new PREClient(g);
    const P = new PREProxy(g);

    A.keyGen();
    B.keyGen();

    const pkA = A.getPk();
    const pkB = B.getPk();
    console.log(pkA.toString('hex'));
    console.log(pkB.toString('hex'));

    //generate random message, recommend it to be symmetric(e.g AES) key.
    const m = crypto.randomBytes(PRE.L0);
    console.log(m.toString('hex'));
    //A encrypt and decrypt on his own
    const encrypted = A.enc(m);
    const [decStatus, decrypted] = A.dec(encrypted);
    console.log(decrypted.toString('hex'), decStatus);

    //A generate reKey(A->B) with B's public key
    const rkey = A.reKeyGen(pkB);
    //P re-encrypt with rkey and encrypted, (use pkA to verify owner of encrypted)
    const [reEncStatus, reEncrypted] = P.reEnc(encrypted, rkey, pkA);
    //now B can decrypt it
    const [reDecStatus, reDecrypted] = B.dec(reEncrypted);
    console.log(reDecrypted.toString('hex'), reDecStatus);

    //anyone can create non-transformable ciphertext using receiver's public key
    const ntEncrypted = B.enc(m, {to: pkA, transformable: false});
    const [ntDecStatus, ntDecrypted] = A.dec(ntEncrypted);
    console.log(ntDecrypted.toString('hex'), ntDecStatus);
    //others cannot decrypt above ciphertext
    const C = new PREClient(g);
    C.keyGen();
    console.log(C.dec(encrypted)[0]);
    console.log(C.dec(reEncrypted)[0]);
    console.log(C.dec(ntEncrypted)[0]);

}).catch(r => {
    console.log(r)
})
```

## Reference
Chow, Sherman SM, et al. "Efficient unidirectional proxy re-encryption." International Conference on Cryptology in Africa. Springer, Berlin, Heidelberg, 2010.