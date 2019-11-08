const mcl = require("mcl-wasm");
const crypto = require("crypto");

class PRE {
  /**
   * Init by L0,L1 and curve
   * @param {number} L0
   * @param {number} L1
   * @param {PRE.CURVE} curve
   * @returns {mcl.G1}
   */
  static async init(L0, L1, curve = PRE.CURVE.SECP256K1) {
    await mcl.init(curve);
    PRE.g = mcl.getBasePointG1();
    PRE.L0 = L0;
    PRE.L1 = L1;
    PRE.L = L0 + L1;
    PRE.L_G = PRE.g.serialize().length;
    PRE.L_Fr = new mcl.Fr().serialize().length;
    return PRE.g
  }

  static get CURVE() {
    return {
      SECP224K1: 101,
      SECP256K1: 102,
      SECP384R1: 103,
      NIST_P192: 105,
      NIST_P224: 106,
      NIST_P256: 107,
    }

  }

  static get C1_LEN() {
    return 2 * PRE.L_G + PRE.L + PRE.L_Fr
  }

  static get C2_LEN() {
    return 2 * PRE.L_G + 2 * PRE.L
  }

  static get REKEY_LEN() {
    return PRE.L_Fr + PRE.L_G + PRE.L
  }

  static get SIG_LEN() {
    return 2 * PRE.L_Fr
  }

  static get STATUS() {
    return {
      VALID: 'VALID',
      ERR_LENGTH: 'ERR_LENGTH',
      ERR_PUB_VERIFY: 'ERR_PUB_VERIFY',
      ERR_DEC1_VERIFY: 'ERR_DEC1_VERIFY',
      ERR_DEC2_VERIFY: 'ERR_DEC2_VERIFY',
    }
  }

  /**
   * Hash Function H1
   * @param {Buffer} m - message buffer with length l0
   * @param {Buffer} w - message buffer with length l1
   * @returns {Object} mcl.Fr
   * @constructor
   */
  static H1(m, w) {
    return mcl.hashToFr(Buffer.concat([w, m]))
  }

  /**
   * Hash Function H2
   * @param {mcl.G1} point
   * @returns {Uint8Array}
   * @constructor
   */
  static H2(point) {
    return crypto.createHash('sha512').update(point.serialize()).digest().slice(0, PRE.L);
  }

  /**
   * Hash Function H3
   * @param {mcl.G1} D
   * @param {mcl.G1} E
   * @param {Buffer} F
   * @returns {mcl.Fr}
   * @constructor
   */
  static H3(D, E, F) {
    return mcl.hashToFr(PRE.xorArrays(F, PRE.xorArrays(PRE.toBuf(E), PRE.toBuf(D))))
  }

  /**
   * H4(pk_2)
   * @param pk2
   * @returns {mcl.Fr}
   */
  static h4pk2(pk2) {
    return mcl.hashToFr(pk2.serialize());
  }

  /**
   * Key Generation
   * @returns {*[]}
   */
  static keyGen() {
    const sk1 = PRE.randomInFr();
    const sk2 = PRE.randomInFr();
    return [[sk1, sk2], PRE.pkFromSk([sk1, sk2])]
  }

  /**
   * reKey Generation
   * @param {mcl.Fr} ska1 A's secret key part 1
   * @param {mcl.Fr} ska2 A's secret key part 2
   * @param {mcl.G1} pka1 A's public key part 1
   * @param {mcl.G1} pka2 A's public key part 2
   * @param {mcl.G1} pkb1 B's public key part 1
   * @param {mcl.G1} pkb2 B's public key part 2
   * @returns {Buffer}
   */
  static reKeyGen([ska1, ska2], [pka1, pka2], [pkb1, pkb2]) {
    const h = crypto.randomBytes(PRE.L0);
    const pi = crypto.randomBytes(PRE.L1);
    const v = PRE.H1(h, pi);
    const hpi = Buffer.concat([h, pi]);
    const V = mcl.mul(pkb2, v); //in G
    const W = PRE.xorArrays(PRE.H2(mcl.mul(PRE.g, v)), hpi);

    const rk = mcl.div(mcl.hashToFr(h), mcl.add(mcl.mul(ska1, PRE.h4pk2(pka2)), ska2)); //in Fr
    return Buffer.concat([PRE.toBuf(rk), PRE.toBuf(V), W])
  }

  /**
   *
   * @param M
   * @param {mcl.G1} pk1
   * @param {mcl.G1} pk2
   * @returns {Buffer} - c1
   */
  static enc1(M, [pk1, pk2]) {
    let m;
    if (typeof (M) === "string")
      m = Buffer.from(M, 'hex');
    else
      m = Buffer.from(M);

    const u = PRE.randomInFr();
    const base = mcl.add(mcl.mul(pk1, PRE.h4pk2(pk2)), pk2);
    const D = mcl.mul(base, u);// in G
    const w = crypto.randomBytes(PRE.L1);
    const r = PRE.H1(m, w);

    const E = mcl.mul(base, r);// in G

    const mw = Buffer.concat([m, w]);
    const f = PRE.H2(mcl.mul(PRE.g, r));
    const F = PRE.xorArrays(f, mw);// Buffer in L_G

    const s = mcl.add(u, mcl.mul(r, PRE.H3(D, E, F)));//in Fr
    return Buffer.concat([PRE.toBuf(D), PRE.toBuf(E), F, PRE.toBuf(s)])


  }

  /**
   *
   * @param M
   * @param {mcl.G1} pk1
   * @param {mcl.G1} pk2
   * @returns {Buffer} - c2
   */
  static enc2(M, [pk1, pk2]) {
    let m;
    if (typeof (M) === "string")
      m = Buffer.from(M, 'hex');
    else
      m = Buffer.from(M);

    const h = crypto.randomBytes(PRE.L0);
    const pi = crypto.randomBytes(PRE.L1);
    const v = PRE.H1(h, pi);
    const hpi = Buffer.concat([h, pi]);
    const V = mcl.mul(pk2, v); //in G
    const W = PRE.xorArrays(PRE.H2(mcl.mul(PRE.g, v)), hpi);
    const w = crypto.randomBytes(PRE.L1);
    const r = PRE.H1(m, w);
    const mw = Buffer.concat([m, w]);
    const f = PRE.H2(mcl.mul(PRE.g, r));
    const F = PRE.xorArrays(f, mw);// Buffer in L_G
    const E1 = mcl.mul(PRE.g, mcl.mul(r, mcl.hashToFr(h)));
    return Buffer.concat([PRE.toBuf(E1), F, PRE.toBuf(V), W])


  }

  /**
   *
   * @param reKey
   * @param {Buffer} c1 - length C1_LEN
   * @param {mcl.G1} pk1
   * @param {mcl.G1} pk2
   * @returns {Array}
   */
  static reEnc(reKey, c1, [pk1, pk2]) {
    if (reKey.length !== PRE.REKEY_LEN || c1.length !== PRE.C1_LEN)
      return [PRE.STATUS.ERR_LENGTH];
    const rk = PRE.bufToFr(reKey.slice(0, PRE.L_Fr));
    const D = PRE.bufToG(c1.slice(0, PRE.L_G));
    const E = PRE.bufToG(c1.slice(PRE.L_G, 2 * PRE.L_G));
    const F = c1.slice(2 * PRE.L_G, 2 * PRE.L_G + PRE.L);
    const s = PRE.bufToFr(c1.slice(2 * PRE.L_G + PRE.L));

    const {status} = PRE.pubVerify([pk1, pk2], [D, E, F, s]);
    if (status === PRE.STATUS.ERR_PUB_VERIFY)
      return [status];
    const E1 = mcl.mul(E, rk); //in G
    return [status, Buffer.concat([PRE.toBuf(E1), F, reKey.slice(PRE.L_Fr)])]

  }

  /**
   * dec1 on c1
   * @param {Buffer} c1 - length C1_LEN
   * @param {mcl.Fr} sk1
   * @param {mcl.Fr} sk2
   * @param {mcl.G1} pk1
   * @param {mcl.G1} pk2
   * @returns {Array}
   */
  static dec1(c1, [sk1, sk2], [pk1, pk2]) {
    if (c1.length !== PRE.C1_LEN)
      return [PRE.STATUS.ERR_LENGTH];
    const D = PRE.bufToG(c1.slice(0, PRE.L_G));
    const E = PRE.bufToG(c1.slice(PRE.L_G, 2 * PRE.L_G));
    const F = c1.slice(2 * PRE.L_G, 2 * PRE.L_G + PRE.L);
    const s = PRE.bufToFr(c1.slice(2 * PRE.L_G + PRE.L));
    const {status, h4pk2, base} = PRE.pubVerify([pk1, pk2], [D, E, F, s]);
    if (status === PRE.STATUS.ERR_PUB_VERIFY)
      return [status];
    const index = mcl.inv(mcl.add(mcl.mul(sk1, h4pk2), sk2));
    const H2EIndex = PRE.H2(mcl.mul(E, index));
    const mw = PRE.xorArrays(F, H2EIndex);
    const m = mw.slice(0, PRE.L0);
    const w = mw.slice(PRE.L0);
    return [PRE.dec1Verify(base, E, m, w), m]

  }

  /**
   * dec 2 on c2
   * @param {Buffer} c2 - length C2_LEN
   * @param {mcl.Fr} sk1
   * @param {mcl.Fr} sk2
   * @param {mcl.G1} pk1
   * @param {mcl.G1} pk2
   * @returns {Array}
   */
  static dec2(c2, [sk1, sk2], [pk1, pk2]) {
    if (c2.length !== PRE.C2_LEN)
      return [PRE.STATUS.ERR_LENGTH];
    const E1 = PRE.bufToG(c2.slice(0, PRE.L_G));
    const F = c2.slice(PRE.L_G, PRE.L_G + PRE.L);
    const V = PRE.bufToG(c2.slice(PRE.L_G + PRE.L, 2 * PRE.L_G + PRE.L));
    const W = c2.slice(2 * PRE.L_G + PRE.L);
    const hpi = PRE.xorArrays(W, PRE.H2(mcl.mul(V, mcl.inv(sk2))));
    const h = hpi.slice(0, PRE.L0);
    const pi = hpi.slice(PRE.L0);
    const mw = PRE.xorArrays(F, PRE.H2(mcl.mul(E1, mcl.inv(mcl.hashToFr(h)))));
    const m = mw.slice(0, PRE.L0);
    const w = mw.slice(PRE.L0);
    return [PRE.dec2Verify(pk2, E1, V, h, pi, m, w), m]

  }

  /**
   * sign message (ECDSA signature)
   * @param {Buffer} m - message to be signed
   * @param {mcl.Fr} sk1
   * @param {mcl.Fr} sk2
   * @param {mcl.G1} pk1
   * @param {mcl.G1} pk2
   * @returns {Buffer} signature
   */
  static sign(m, [sk1, sk2], [pk1, pk2]) {
    const z = mcl.hashToFr(m);
    const k = PRE.randomInFr();
    const r = new mcl.Fr();
    r.setLittleEndianMod(mcl.mul(PRE.g, k).serialize());
    const h4pk2 = PRE.h4pk2(pk2);
    const base = mcl.add(mcl.mul(sk1, h4pk2), sk2);
    const s = mcl.mul(mcl.inv(k), mcl.add(z, mcl.mul(r, base)));
    return Buffer.concat([PRE.toBuf(r), PRE.toBuf(s)])

  }

  /**
   * verify signature
   * @param {Buffer} m - message to be signed
   * @param {Buffer} sig - signature
   * @param {mcl.G1} pk1
   * @param {mcl.G1} pk2
   * @returns {boolean}
   */
  static verify(m, sig, [pk1, pk2]) {
    if (sig.length !== PRE.SIG_LEN)
      return false;
    const r = PRE.bufToFr(sig.slice(0, PRE.L_Fr));
    const s = PRE.bufToFr(sig.slice(PRE.L_Fr));
    const z = mcl.hashToFr(m);
    const h4pk2 = PRE.h4pk2(pk2);
    const base2 = mcl.add(mcl.mul(pk1, h4pk2), pk2);
    const w = mcl.inv(s);
    const u1 = mcl.mul(z, w);
    const u2 = mcl.mul(r, w);
    const rr = new mcl.Fr();
    rr.setLittleEndianMod(mcl.add(mcl.mul(PRE.g, u1), mcl.mul(base2, u2)).serialize());
    return rr.isEqual(r)
  }

  /**
   * xor 2 arrays
   * @param {Uint8Array|Buffer} a1
   * @param {Uint8Array|Buffer} a2
   * @returns {Buffer}
   */
  static xorArrays(a1, a2) {
    const l = a1.length;
    const r = Buffer.alloc(l);
    for (let i = 0; i < l; i++)
      r[i] = a1[i] ^ a2[i];
    return r

  }

  /**
   * verify can be performed by anyone on enc1 result
   * @param {mcl.G1} pk1 - public key part 1
   * @param {mcl.G1} pk2 - public key part 2
   * @param {mcl.G1} D
   * @param {mcl.G1} E
   * @param {Buffer} F - length l0+l1=l
   * @param {mcl.Fr} s
   * @returns {{h4pk2: mcl.Fr, status: string, base: *}}
   */
  static pubVerify([pk1, pk2], [D, E, F, s]) {
    const h4pk2 = PRE.h4pk2(pk2);
    const base = mcl.add(mcl.mul(pk1, h4pk2), pk2);
    const lhs = mcl.mul(base, s);
    const rhs = mcl.add(D, mcl.mul(E, PRE.H3(D, E, F)));

    return {
      status: lhs.isEqual(rhs) ? PRE.STATUS.VALID : PRE.STATUS.ERR_PUB_VERIFY,
      h4pk2,
      base
    };
  }

  /**
   * verify in dec1
   * @param {mcl.G1} base - pk1^H4(pk2)*pk2
   * @param {mcl.G1} E
   * @param {Buffer} m - length L0
   * @param {Buffer} w - length L1
   * @returns {string}
   */
  static dec1Verify(base, E, m, w) {
    return E.isEqual(mcl.mul(base, PRE.H1(m, w))) ?
      PRE.STATUS.VALID : PRE.STATUS.ERR_DEC1_VERIFY
  }

  /**
   * verify in dec2
   * @param {mcl.G1} pk2 - public key part 2
   * @param {mcl.G1} E1
   * @param {mcl.G1} V
   * @param {Buffer} h - length L0
   * @param {Buffer} pi - length L1
   * @param {Buffer} m - length L0
   * @param {Buffer} w - length L1
   * @returns {PRE.STATUS}
   */
  static dec2Verify(pk2, E1, V, h, pi, m, w) {
    const isValid =
      V.isEqual(mcl.mul(pk2, PRE.H1(h, pi))) &&
      E1.isEqual(mcl.mul(this.g, mcl.mul(PRE.H1(m, w), mcl.hashToFr(h))));
    return isValid ? PRE.STATUS.VALID : PRE.STATUS.ERR_DEC2_VERIFY
  }

  /**
   * return random element in Fr
   * @returns {mcl.Fr}
   */
  static randomInFr() {
    const r = new mcl.Fr();
    r.setByCSPRNG();
    return r
  }

  /**
   * Buffer to G1 element
   * @param {Buffer} buf
   * @returns {mcl.G1}
   */
  static bufToG(buf) {
    const point = new mcl.G1();
    point.deserialize(buf);
    return point
  }

  /**
   * Buffer to Fr element
   * @param {Buffer} buf
   * @returns {mcl.Fr}
   */
  static bufToFr(buf) {
    const point = new mcl.Fr();
    point.deserialize(buf);
    return point
  }

  /**
   * point/Fr to buffer
   * @param {mcl.G1|mcl.Fr} point
   * @returns {Buffer}
   */
  static toBuf(point) {
    return Buffer.from(point.serialize())
  }

  /**
   * return pk From sk
   * @param sk1 secret key part 1
   * @param sk2 secret key part 2
   * @returns {mcl.G1[]}
   */
  static pkFromSk([sk1, sk2]) {
    const pk1 = mcl.mul(PRE.g, sk1);
    const pk2 = mcl.mul(PRE.g, sk2);
    return [pk1, pk2]
  }

  /**
   * key to Buffer
   * @param {mcl.G1[]|mcl.Fr[]} key
   * @returns {Buffer}
   */
  static keyToBuf(key) {
    return Buffer.concat([
      Buffer.from(key[0].serialize()),
      Buffer.from(key[1].serialize())
    ])
  }

  /**
   * pk to Fr
   * @param {string|Buffer|Array} pk
   * @returns {mcl.G1[]}
   */
  static parsePk(pk) {
    let buf = undefined;
    if (typeof pk === "string")
      buf = Buffer.from(pk, 'hex');
    else if (Buffer.isBuffer(pk))
      buf = pk;
    if (buf === undefined)
      return pk;
    const pk1 = PRE.bufToG(buf.slice(0, PRE.L_G));
    const pk2 = PRE.bufToG(buf.slice(PRE.L_G));
    return [pk1, pk2];
  }

  /**
   * sk to Fr
   * @param {string|Buffer|Array} sk
   * @returns {mcl.Fr[]}
   */
  static parseSk(sk) {
    let buf = undefined;
    if (typeof sk === "string")
      buf = Buffer.from(sk, 'hex');
    else if (Buffer.isBuffer(sk))
      buf = sk;
    if (buf === undefined)
      return sk;
    const sk1 = PRE.bufToFr(buf.slice(0, PRE.L_Fr));
    const sk2 = PRE.bufToFr(buf.slice(PRE.L_Fr));
    return [sk1, sk2];

  }

}

class PREClient {
  constructor() {
    this.pk = null;
    this.sk = null;
  }

  keyGen() {
    [this.sk, this.pk] = PRE.keyGen();
    return [this.sk, this.pk]
  }

  loadKey(sk) {
    this.sk = PRE.parseSk(sk);
    this.pk = PRE.pkFromSk(this.sk);

  }

  getSk() {
    return PRE.keyToBuf(this.sk)
  }

  getPk() {
    return PRE.keyToBuf(this.pk)
  }

  reKeyGen(to) {
    to = PRE.parsePk(to);
    return PRE.reKeyGen(this.sk, this.pk, to)

  }

  enc(M, {to = this.pk, transformable = true} = {}) {
    to = PRE.parsePk(to);
    if (transformable)
      return PRE.enc1(M, to);
    else
      return PRE.enc2(M, to);
  }

  dec(C) {
    return C.length === PRE.C1_LEN ?
      PRE.dec1(C, this.sk, this.pk) :
      PRE.dec2(C, this.sk, this.pk)

  }

  sign(M) {
    return PRE.sign(M, this.sk, this.pk)
  }

  static verify(M, sig, from) {
    from = PRE.parsePk(from);
    return PRE.verify(M, sig, from)
  }


}

class PREProxy {
  static reEnc(C1, reKey, owner) {
    owner = PRE.parsePk(owner);
    return PRE.reEnc(reKey, C1, owner)
  }
}

module.exports = {PRE, PREClient, PREProxy};
