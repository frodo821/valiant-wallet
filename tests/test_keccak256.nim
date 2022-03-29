# This is just an example to get you started. You may wish to put all of your
# tests into a single file, or separate them into multiple `test1`, `test2`
# etc. files (better names are recommended, just make sure the name starts with
# the letter 't').
#
# To run these tests, simply execute `nimble test`.

import unittest
import valiant_wallet/crypt/keccak256


suite "can calculate keccak256 hash":
    setup:
        var state = initState()

    test "hash a string":
        state.update("Hello, Nim!!")
        check(state.digest().hex() == "0d9c394787b1daacaef8aa8839a2432c9bee40010e087e2983910c0cd4ff78ad")

    test "hash an array of byte":
        state.update("Hello, Nim!!".toOpenArrayByte(0, 11))
        check(state.digest().hex() == "0d9c394787b1daacaef8aa8839a2432c9bee40010e087e2983910c0cd4ff78ad")

    test "hash an array of uint8 array":
        state.update([72'u8, 101'u8, 108'u8, 108'u8, 111'u8, 44'u8, 32'u8, 78'u8, 105'u8, 109'u8, 33'u8, 33'u8])
        check(state.digest().hex() == "0d9c394787b1daacaef8aa8839a2432c9bee40010e087e2983910c0cd4ff78ad")

    test "hash of empty bytes":
        check(state.digest().hex() == "0d9c394787b1daacaef8aa8839a2432c9bee40010e087e2983910c0cd4ff78ad")
