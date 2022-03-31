import unittest
import valiant_wallet/crypt/[ecdsa, elliptic/secp256k1]


let prikey = 0xc0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0de'bi #'
let pubkey = 0x44643bb6b393ac20a6175c713175734a72517c63d6f73a3ca90a15356f2e967da03d16431441c61ac69aeabb7937d333829d9da50431ff6af38536aa262497b27'bi #'
let curve: Curve = secp256k1.secp256k1
let presigned = "0x6a9e75800cfb5302a6ca216ae22d95c333359988aa6a97e472a99c9918c2ff602e9e268db1417f7aae7470e69af2dc7829180a44633c4f9abdcedcb7394f5dfb1b".deserialize()
let message = "\x19Ethereum Signed Message:\n17Hello, Nim-lang!!"

suite "elliptic curve operations":
    setup:
        let base = curve.params.G

    test "multiplication by scalar":
        check:
            curve.double(base) == Point(
                x: 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5'bi, #'
                y: 0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A'bi #'
            )
        check:
            curve.multiply(base, 3'bi) == Point(
                x: 0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9'bi, #'
                y: 0x388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672'bi #'
            )
        check:
            curve.multiply(base, 4'bi) == Point(
                x: 0xE493DBF1C10D80F3581E4904930B1404CC6C13900EE0758474FA94ABE8C4CD13'bi, #'
                y: 0x51ED993EA0D455B75642E2098EA51448D967AE33BFBDFE40CFE97BDC47739922'bi #'
            )
        check:
            curve.multiply(base, 5'bi) == Point(
                x: 0x2F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4'bi, #'
                y: 0xD8AC222636E5E3D6D4DBA9DDA6C9C426F788271BAB0D6840DCA87D3AA6AC62D6'bi #'
            )
        check:
            curve.multiply(base, 115792089237316195423570985008687907852837564279074904382605163141518161494335'bi) == Point(
                x: 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5'bi, #'
                y: 0xE51E970159C23CC65C3A7BE6B99315110809CD9ACD992F1EDC9BCE55AF301705'bi #'
            )
        check:
            curve.multiply(base, 115792089237316195423570985008687907852837564279074904382605163141518161494336'bi) == Point(
                x: 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798'bi, #'
                y: 0xB7C52588D95C3B9AA25B0403F1EEF75702E84BB7597AABE663B82F6F04EF2777'bi #'
            )
        check:
            curve.multiply(base, curve.params.N).isInfinite()

suite "generate key pair":
    test "derive public key from private key":
        check(curve.derivePubKeyFromSecret(prikey) == pubkey)

suite "sign message and find public key":
    test "consistency of signature serialization and deserialization":
        check(presigned.serialize.deserialize == presigned)

    test "ecdsa verifying":
        check(curve.verifySignature(pubkey, message, presigned))

    test "ecdsa signing":
        check(curve.verifySignature(pubkey, message, curve.createSignature(prikey, message)))

    test "recover public key from signed message with parity":
        let sig = curve.createSignature(prikey, message)
        let rpk = curve.recoverPubKey(message, sig)
        echo "signature: " & sig.serialize
        check(curve.toUncompressed(rpk).toString(16) == pubkey.toString(16))
