import bigints
import ./elliptic/curve
import ./keccak256
export bigints
export curve

type
    KeyPair* = object
        secret*: BigInt
        public*: BigInt

proc generateKeyPair*(cur: Curve, seed: BigInt): KeyPair =
    result.secret = hexDigestOf(seed).initBigInt(16)
    result.public = cur.derivePubKeyFromSecret(result.secret)

proc derivePubKeyFromSecret*(cur: Curve, secret: BigInt): BigInt = cur.toUncompressed(cur.multiplyBase(secret))
