import unittest
import valiant_wallet/account

let prikey = "0xc0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0de"
let pubkey = 0x44643bb6b393ac20a6175c713175734a72517c63d6f73a3ca90a15356f2e967da03d16431441c61ac69aeabb7937d333829d9da50431ff6af38536aa262497b27'bi #'
let address = "0x53Ae893e4b22D707943299a8d0C844Df0e3d5557".Address
let message = "Hello, world!"

suite "general account control":
    test "checksum calculations":
        check(address.isValidAddress())

    test "initialize account":
        let sk = prikey.initAccountWithSecretKey()

        check(sk.keypair.public == pubkey)
        check(sk.address == address)

    test "sign message with account and verify with address":
        let sk = prikey.initAccountWithSecretKey()

        check(address.verifySignature(message, sk.signMessage(message)))
