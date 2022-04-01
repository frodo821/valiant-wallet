import crypt/[keccak256, ecdsa, elliptic/secp256k1]
export keccak256, ecdsa, secp256k1

type
    Address* = distinct string
    Account* = ref object
        address*: Address
        keypair*: KeyPair

const curve = secp256k1.secp256k1

proc `==`*(a: Address, b: Address): bool {.borrow.}

proc encodeAddress(address: string): Address =
    let digest = address.digestOf()
    var res = "0x"

    for i, c in address:
        let j = i div 2
        let m = i and 1

        if m == 1:
            if (cast[uint8](digest[j]) and 0x0F) > 7:
                res.add(address[i].toUpperAscii)
            else:
                res.add(address[i])
            continue

        if (cast[uint8](digest[j]) shr 4) > 7:
            res.add(address[i].toUpperAscii)
        else:
            res.add(address[i])

    return res.Address

proc isValidAddress*(address: Address): bool =
    let astr = cast[string](address)

    if not (astr.len == 42 and astr.startsWith("0x")):
        return false

    if astr == astr.toLowerAscii:
        return true

    let digest = astr.toLower.substr(2).digestOf()

    for i, c in astr.substr(2):
        let j = i div 2
        let m = i and 1
        let shouldUpper = (if m == 1: cast[uint8](digest[j]) and 0x0F else: cast[uint8](digest[j]) shr 4) > 7

        if c.isAlphaAscii and (c.isUpperAscii xor shouldUpper):
            return false

    return true

proc ensureAddress*(maybeAddress: string): Address =
    let address = maybeAddress.Address
    if address.isValidAddress():
        return address

    var err = new ValueError
    err.msg = "invalid address"
    raise err

proc createAddressFromPublicKey*(pubkey: BigInt): Address {.inline.} =
    pubkey.toString(16).substr(1).parseHexStr.hexDigestOf.substr(24).encodeAddress()

proc initAccountWithSecretKey*(secretKey: string): Account =
    if not (secretKey.startsWith("0x") and secretKey.len == 66):
        var err = new ValueError
        err.msg = "invalid secret key"
        raise err
    new result

    result.keypair = curve.createKeyPairWithSecret(secretKey.substr(2).initBigInt(16))
    result.address = encodeAddress(result.keypair.public.toString(16).substr(1).parseHexStr.hexDigestOf.substr(24))
