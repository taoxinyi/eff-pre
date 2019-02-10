const mcl = require("mcl-wasm");
const crypto = require("crypto");

class PRE {
    /**
     * init generator g
     * @returns {Promise<mcl.G1>}
     */
    static async init() {
        await mcl.init(mcl.BLS12_381);
        return mcl.hashAndMapToG1("tttt");
    }

    static get L0() {
        return 32
    }

    static get L1() {
        return 16
    }

    static get L() {
        return 48
    }

    static get C1LEN() {
        return 176
    }

    static get C2LEN() {
        return 192
    }

    static get STATUS() {
        return {
            VALID: 'VALID',
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
        return mcl.hashAndMapToG1(point.serialize()).serialize();
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

    static keyGen(g) {
        const sk1 = PRE.randomInFr();
        const sk2 = PRE.randomInFr();
        return [[sk1, sk2], PRE.pkFromSk(g, [sk1, sk2])]
    }

    static reKeyGen(g, [ska1, ska2], [pka1, pka2], [pkb1, pkb2]) {
        const h = crypto.randomBytes(PRE.L0);
        const pi = crypto.randomBytes(PRE.L1);
        const v = PRE.H1(h, pi);
        const hpi = Buffer.concat([h, pi]);
        const V = mcl.mul(pkb2, v); //in G
        const W = PRE.xorArrays(PRE.H2(mcl.mul(g, v)), hpi);

        const rk = mcl.div(mcl.hashToFr(h), mcl.add(mcl.mul(ska1, PRE.h4pk2(pka2)), ska2)); //in Fr
        return Buffer.concat([PRE.toBuf(rk), PRE.toBuf(V), W])


    }

    static enc1(g, M, [pk1, pk2]) {
        let m;
        if (typeof (M) === "string")
            m = new Buffer(M, 'hex');
        else
            m = new Buffer(M);

        const u = PRE.randomInFr();
        const base = mcl.add(mcl.mul(pk1, PRE.h4pk2(pk2)), pk2);
        const D = mcl.mul(base, u);// in G
        const w = crypto.randomBytes(PRE.L1);
        const r = PRE.H1(m, w);

        const E = mcl.mul(base, r);// in G

        const mw = Buffer.concat([m, w]);
        const f = PRE.H2(mcl.mul(g, r));
        const F = PRE.xorArrays(f, mw);// Buffer in L

        const s = mcl.add(u, mcl.mul(r, PRE.H3(D, E, F)));//in Fr

        return Buffer.concat([PRE.toBuf(D), PRE.toBuf(E), F, PRE.toBuf(s)])


    }

    static enc2(g, M, [pk1, pk2]) {
        let m;
        if (typeof (M) === "string")
            m = new Buffer(M, 'hex');
        else
            m = new Buffer(M);

        const h = crypto.randomBytes(PRE.L0);
        const pi = crypto.randomBytes(PRE.L1);
        const v = PRE.H1(h, pi);
        const hpi = Buffer.concat([h, pi]);
        const V = mcl.mul(pk2, v); //in G
        const W = PRE.xorArrays(PRE.H2(mcl.mul(g, v)), hpi);
        const w = crypto.randomBytes(PRE.L1);
        const r = PRE.H1(m, w);
        const mw = Buffer.concat([m, w]);
        const f = PRE.H2(mcl.mul(g, r));
        const F = PRE.xorArrays(f, mw);// Buffer in L
        const E1 = mcl.mul(g, mcl.mul(r, mcl.hashToFr(h)));
        return Buffer.concat([PRE.toBuf(E1), F, PRE.toBuf(V), W])


    }

    static reEnc(g, reKey, encrypted, [pk1, pk2]) {
        const rk = PRE.bufToFr(reKey.slice(0, PRE.L0));
        const D = PRE.bufToG(encrypted.slice(0, PRE.L));
        const E = PRE.bufToG(encrypted.slice(PRE.L, 2 * PRE.L));
        const F = encrypted.slice(2 * PRE.L, 3 * PRE.L);
        const s = PRE.bufToFr(encrypted.slice(3 * PRE.L));

        const {status} = PRE.pubVerify(g, [pk1, pk2], [D, E, F, s]);
        if (status === PRE.STATUS.ERR_PUB_VERIFY)
            return [status];
        const E1 = mcl.mul(E, rk); //in G
        return [status, Buffer.concat([PRE.toBuf(E1), encrypted.slice(2 * PRE.L, 3 * PRE.L), reKey.slice(PRE.L0)])]

    }

    static dec1(g, encrypted, [sk1, sk2], [pk1, pk2]) {
        const D = PRE.bufToG(encrypted.slice(0, PRE.L));
        const E = PRE.bufToG(encrypted.slice(PRE.L, 2 * PRE.L));
        const F = encrypted.slice(2 * PRE.L, 3 * PRE.L);
        const s = PRE.bufToFr(encrypted.slice(3 * PRE.L));
        const {status, h4pk2, base} = PRE.pubVerify(g, [pk1, pk2], [D, E, F, s]);
        if (status === PRE.STATUS.ERR_PUB_VERIFY)
            return [status];
        const index = mcl.inv(mcl.add(mcl.mul(sk1, h4pk2), sk2));
        const H2EIndex = PRE.H2(mcl.mul(E, index));
        const mw = PRE.xorArrays(F, H2EIndex);
        const m = mw.slice(0, PRE.L0);
        const w = mw.slice(PRE.L0);
        return [PRE.dec1Verify(base, E, m, w), m]

    }

    static dec2(g, reEncrypted, [sk1, sk2], [pk1, pk2]) {
        const E1 = PRE.bufToG(reEncrypted.slice(0, PRE.L));
        const F = reEncrypted.slice(PRE.L, 2 * PRE.L);
        const V = PRE.bufToG(reEncrypted.slice(2 * PRE.L, 3 * PRE.L));
        const W = reEncrypted.slice(3 * PRE.L);
        const hpi = PRE.xorArrays(W, PRE.H2(mcl.mul(V, mcl.inv(sk2))));
        const h = hpi.slice(0, PRE.L0);
        const pi = hpi.slice(PRE.L0);
        const mw = PRE.xorArrays(F, PRE.H2(mcl.mul(E1, mcl.inv(mcl.hashToFr(h)))));
        const m = mw.slice(0, PRE.L0);
        const w = mw.slice(PRE.L0);
        return [PRE.dec2Verify(g, pk2, E1, V, h, pi, m, w), m]

    }


    /**
     *
     * @param {Uint8Array|Buffer} a1
     * @param {Uint8Array|Buffer} a2
     * @returns {Buffer}
     */
    static xorArrays(a1, a2) {
        const l = a1.length;
        const r = new Buffer(l);
        for (let i = 0; i < l; i++)
            r[i] = a1[i] ^ a2[i]
        return r

    }

    static pubVerify(g, [pk1, pk2], [D, E, F, s]) {
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

    static dec1Verify(base, E, m, w) {
        return E.isEqual(mcl.mul(base, PRE.H1(m, w))) ?
            PRE.STATUS.VALID : PRE.STATUS.ERR_DEC1_VERIFY
    }

    static dec2Verify(g, pk2, E1, V, h, pi, m, w) {
        const isValid =
            V.isEqual(mcl.mul(pk2, PRE.H1(h, pi))) &&
            E1.isEqual(mcl.mul(g, mcl.mul(PRE.H1(m, w), mcl.hashToFr(h))));
        return isValid ? PRE.STATUS.VALID : PRE.STATUS.ERR_DEC2_VERIFY
    }

    static randomInFr() {
        const r = new mcl.Fr();
        r.setByCSPRNG();
        return r
    }

    static bufToG(buf) {
        const point = new mcl.G1();
        point.deserialize(buf);
        return point
    }

    static bufToFr(buf) {
        const point = new mcl.Fr();
        point.deserialize(buf);
        return point
    }

    static toBuf(point) {
        return new Buffer(point.serialize())
    }


    static pkFromSk(g, [sk1, sk2]) {
        const pk1 = mcl.mul(g, sk1);
        const pk2 = mcl.mul(g, sk2);
        return [pk1, pk2]
    }

    static keyToBuf(key) {
        return Buffer.concat([
            new Buffer(key[0].serialize()),
            new Buffer(key[1].serialize())
        ])
    }

    static parsePk(pk) {
        let buf = undefined;
        if (typeof pk === "string")
            buf = new Buffer(pk, 'hex');
        else if (Buffer.isBuffer(pk))
            buf = pk;
        if (buf === undefined)
            return pk;
        const pk1 = PRE.bufToG(buf.slice(0, PRE.L));
        const pk2 = PRE.bufToG(buf.slice(PRE.L));
        return [pk1, pk2];
    }

    static parseSk(sk) {
        let buf = undefined;
        if (typeof sk === "string")
            buf = new Buffer(sk, 'hex');
        else if (Buffer.isBuffer(sk))
            buf = sk;
        if (buf === undefined)
            return sk;
        const sk1 = PRE.bufToFr(buf.slice(0, PRE.L0));
        const sk2 = PRE.bufToFr(buf.slice(PRE.L0));
        return [sk1, sk2];

    }

}
module.exports = PRE;

