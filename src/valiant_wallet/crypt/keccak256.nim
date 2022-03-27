type
    HashWords {.union.} = object
        words: array[25, uint64]
        bytes: array[200, uint8]

    HashState* = ref object
        hw: HashWords
        reading: 0..135

const iotaConstants: array[24, uint64] = [
        0x0000000000000001'u64, 0x0000000000008082'u64, 0x800000000000808a'u64,
        0x8000000080008000'u64, 0x000000000000808b'u64, 0x0000000080000001'u64,
        0x8000000080008081'u64, 0x8000000000008009'u64, 0x000000000000008a'u64,
        0x0000000000000088'u64, 0x0000000080008009'u64, 0x000000008000000a'u64,
        0x000000008000808b'u64, 0x800000000000008b'u64, 0x8000000000008089'u64,
        0x8000000000008003'u64, 0x8000000000008002'u64, 0x8000000000000080'u64,
        0x000000000000800a'u64, 0x800000008000000a'u64, 0x8000000080008081'u64,
        0x8000000000008080'u64, 0x0000000080000001'u64, 0x8000000080008008'u64,
]

const rotOffsets: array[25, uint64] = [
     0'u64,  1'u64, 62'u64, 28'u64, 27'u64,
    36'u64, 44'u64,  6'u64, 55'u64, 20'u64,
     3'u64, 10'u64, 43'u64, 25'u64, 39'u64,
    41'u64, 45'u64, 15'u64, 21'u64,  8'u64,
    18'u64,  2'u64, 61'u64, 56'u64, 14'u64,
]

const hexDigits = "0123456789abcdef"

template rot64(x: uint64, k: uint64): uint64 = (x shl k) or (x shr (64 - k))

template round(state: var HashState, iterations: int) =
    var b: array[25, uint64]
    var c: array[5, uint64]
    var d: array[5, uint64]

    for i in 0..4:
        c[i] = state.hw.words[i] xor state.hw.words[i + 5] xor state.hw.words[i + 10] xor state.hw.words[i + 15] xor state.hw.words[i + 20]

    for i in 0..4:
        d[i] = c[(i + 4) mod 5] xor rot64(c[(i + 1) mod 5], 1)

    for i in 0..24:
        state.hw.words[i] = state.hw.words[i] xor d[i mod 5]

    for x in 0..4:
        for y in 0..4:
            let i = x + 5*y
            b[((2*x + 3*y) mod 5) * 5 + y] = rot64(state.hw.words[i], rotOffsets[i])

    for x in 0..4:
        for y in 0..4:
            let i = x + 5*y
            state.hw.words[i] = b[i] xor ((not b[(x + 1) mod 5 + y*5]) and b[(x + 2) mod 5 + y*5])

    state.hw.words[0] = state.hw.words[0] xor iotaConstants[iterations]

template keccakF1600(state: var HashState) =
    for i in 0..23:
        round(state, i)

proc initState*(): HashState =
    ## initialize hash state
    runnableExamples:
        var state = initState()
        state.update("Hello, World!!")
        echo state.digest()

    new result
    for i in 0..24:
        result.hw.words[i] = 0
    result.reading = 0

proc update*(state: var HashState, bytes: openArray[uint8]) =
    ## feed data to hasher
    for c in bytes:
        state.hw.bytes[state.reading] = state.hw.bytes[state.reading] xor c
        state.reading = if (state.reading == 135): 0 else: state.reading + 1

        if state.reading == 0:
            state.keccakF1600()

proc update*[T: string or openArray[byte]](state: var HashState, bytes: T) =
    ## feed data to hasher
    for c in bytes:
        state.hw.bytes[state.reading] = state.hw.bytes[state.reading] xor cast[uint8](c)
        state.reading = if (state.reading == 135): 0 else: state.reading + 1

        if state.reading == 0:
            state.keccakF1600()

proc digest*(state: var HashState): string =
    ## calculate digest
    ## please note this procedure breaks the hasher internal state and re-initializes it.
    result = ""

    state.hw.bytes[state.reading] = state.hw.bytes[state.reading] xor 0x06
    state.hw.bytes[135] = state.hw.bytes[135] xor 0x80

    state.keccakF1600()

    for i in 0..31:
        result.add(cast[char](state.hw.bytes[i]))

    state.reading = 0
    for i in 0..24:
        state.hw.words[i] = 0

proc hex*(str: string): string =
    ## convert string to hexadecimal string
    result = ""

    for c in str:
        result.add(hexDigits[cast[uint8](c) shr 4])
        result.add(hexDigits[cast[uint8](c) and 0x0f])

when isMainModule:
    var state = initState()
    state.update("Hello, Nim-lang!!")
    let dig = state.digest().hex()
    assert dig == "0f3be9c96b48b5e4dd07da8e0141ba75ee3b6fcbc75cb1323225d09084344af1"
