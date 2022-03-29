import unittest
import valiant_wallet/crypt/[ecdsa, elliptic/secp256k1]

suite "generate key pair":
    setup:
        let prikey = 0xc0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0de'bi #'
        let pubkey = 0x44643bb6b393ac20a6175c713175734a72517c63d6f73a3ca90a15356f2e967da03d16431441c61ac69aeabb7937d333829d9da50431ff6af38536aa262497b27'bi #'
        let curve: Curve = secp256k1.secp256k1

    test "derive public key from private key":
        check(curve.derivePubKeyFromSecret(prikey) == pubkey)
