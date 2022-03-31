import bigints, std/sysrand
import ./elliptic/curve
import ./keccak256
export bigints, curve, keccak256

type
    KeyPair* = object
        secret*: BigInt
        public*: BigInt

    Signature* = object
        r: BigInt
        s: BigInt
        v: uint8

let zerob = 0.initBigInt()
let oneb = 1.initBigInt()

template `==`*(s1: Signature, s2: Signature): bool = (s1.r == s2.r and s1.s == s2.s and s1.v == s2.v)

proc generateKeyPair*(cur: Curve, seed: BigInt): KeyPair =
    result.secret = hexDigestOf(seed).initBigInt(16) mod cur.params.N
    result.public = cur.derivePubKeyFromSecret(result.secret)

proc derivePubKeyFromSecret*(cur: Curve, secret: BigInt): BigInt = cur.toUncompressed(cur.multiplyBase(secret))

proc createSignature*[T: Digestable](cur: Curve, secret: BigInt, message: T, networkId: uint = 1): Signature =
    let z = hexDigestOf(message).substr(0, cast[int](cur.params.BitSize div 4 - 1)).initBigInt(16)

    while true:
        let k = hexDigestOf[seq[byte]](urandom(64)).initBigInt(16) mod cur.params.N
        let p = cur.multiplyBase(k)
        let r = p.x

        if r == zerob or r > cur.params.N:
            continue

        let s = (invmod(k, cur.params.N) * (z + r * secret)) mod cur.params.N

        if s == zerob or (s shl 1) > cur.params.N:
            continue

        return Signature(
            r: r, s: s,
            v: (if (p.y and 1'bi) == 0: 28 else: 27) #'
        )

proc serialize*(sig: Signature): string =
    var r = sig.r.toString(16)
    var s = sig.s.toString(16)
    var v = sig.v.toHex(2)

    if r.len < 64:
        r = "0".repeat(64 - r.len) & r
    if s.len < 64:
        s = "0".repeat(64 - s.len) & s

    return "0x" & r & s & v.toLower

proc deserialize*(sig: string): Signature =
    let r = sig.substr(2, 65).initBigInt(16)
    let s = sig.substr(66, 129).initBigInt(16)
    let v = cast[uint8](sig.substr(130).parseHexInt())

    return Signature(r: r, s: s, v: v)

proc verifySignature*[T: Digestable](cur: Curve, pubkey: BigInt, message: T, signature: Signature): bool =
    let key = cur.decomposite(pubkey)

    if key.isInfinite or not cur.isOnCurve(key) or cur.multiply(key, cur.params.N).isFinite:
        var err = new ValueError
        err.msg = "public key is not valid"
        raise err

    let r = signature.r
    let s = signature.s

    if r < zerob or r >= cur.params.N or s < zerob or s >= cur.params.N:
        return false

    let z = hexDigestOf(message).substr(0, cast[int](cur.params.BitSize div 4 - 1)).initBigInt(16)
    let w = invmod(s, cur.params.N)
    let u1 = (z * w) mod cur.params.N
    let u2 = (r * w) mod cur.params.N
    let p = cur.add(cur.multiply(cur.params.G, u1), cur.multiply(key, u2))

    return p.x == r

proc calcPointFromXCoord(cur: Curve, px: BigInt, parity: bool): Point {.inline.} =
    # curve parameter P must be a odd prime
    # so we assert it must be an odd number.
    assert (cur.params.P and oneb) == oneb

    # y^2 = x^3 + b
    let ysq = pow(px, 3) + cur.params.B

    # we assure that ysq is a quadratic residue modulo P
    if powmod(ysq, cur.params.P shr 1, cur.params.P) != oneb:
        var err = new ValueError
        err.msg = "malformed signature"
        raise err

    # if P is a prime number congruent with 3 modulo 4,
    # (P+1) / 4 power to ysq is the quadratic residue modulo P to be found
    if (cur.params.P and 0x03.initBigInt) == 3:
        let y = powmod(ysq, (cur.params.P + oneb) shr 2, cur.params.P)

        # if parity is even, y must be positive
        if parity:
            return Point(x: px, y: y)
        # otherwise, y must be negative
        return Point(x: px, y: cur.params.P - y)

    # otherwise, in short, when P is a prime congruent with 1 modulo 4,
    # we can use the Tonelli-Shanks algorithm to find quadratic residue modulo P.

    let (q, s) = block:
        var tq = cur.params.P - oneb
        var ts = 0

        while (tq and oneb) == zerob:
            tq = tq shr 1
            ts += 1

        (tq, ts)

    let z = block:
        var tz = oneb
        var pl = cur.params.P - oneb
        while true:
            if powmod(tz, cur.params.P shr 1, cur.params.P) == pl:
                break
            tz = tz + oneb
        tz

    var m = s
    var c = powmod(z, q, cur.params.P)
    var t = powmod(ysq, q, cur.params.P)
    var r = powmod(ysq, (q + oneb) shr 1, cur.params.P)

    while t != oneb:
        let j = block:
            var tj = 1
            while powmod(t, oneb shl tj, cur.params.P) != oneb:
                tj += 1
            tj
        let cn = powmod(c, oneb shl (m - j - 1), cur.params.P)
        let cnsq = (cn * cn) mod cur.params.P
        r = (r * cn) mod cur.params.P
        t = (t * cnsq) mod cur.params.P
        c = cnsq
        m = j

    # if parity is even, y must be positive
    if parity:
        return Point(x: px, y: r)
    # otherwise, y must be negative
    return Point(x: px, y: cur.params.P - r)

proc recoverPubKey*[T: Digestable](cur: Curve, message: T, signature: Signature): Point =
    let z = hexDigestOf(message).substr(0, cast[int](cur.params.BitSize div 4 - 1)).initBigInt(16)
    let r = signature.r
    let s = signature.s
    let v = signature.v

    # parity of x coordination of k*G
    # true if x is even
    let parity = (v and 1) == 0

    if r < zerob or r >= cur.params.N or s < zerob or s >= cur.params.N:
        var err = new ValueError
        err.msg = "malformed signature"
        raise err

    let kp = cur.calcPointFromXCoord(r, parity)
    let rinv = invmod(r, cur.params.P)

    return cur.multiply(cur.add(cur.multiply(kp, s), (-cur.multiply(cur.params.G, z)) mod cur.params.P), rinv)
