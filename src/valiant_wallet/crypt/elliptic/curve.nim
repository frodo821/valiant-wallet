import bigints, strutils
export bigints, strutils

type
    ## A coordinate in a 2-dimensional space.
    Point* = object
        ## The x coordinate of the point
        x*: BigInt
        ## The y coordinate of the point
        y*: BigInt

    ## Elliptic curve parameters
    CurveParams* = object
        ## The prime modulus
        P*: BigInt
        ## The order of the curve
        N*: BigInt
        ## The cofactor of the curve
        B*: BigInt
        ## The base point
        G*: Point
        ## The length in bits of the order of the curve
        BitSize*: int64
        ## The name of the curve
        Name*: string

    ## Elliptic curve
    Curve* = concept x
        x.params() is CurveParams

const zerob = 0.initBigInt
const oneb = 1.initBigInt

template `==`*(x: BigInt, y: int): bool = x == initBigInt(y)

template `==`*(p1: Point, p2: Point): bool = (p1.x == p2.x) and (p1.y == p2.y)

template b(value: int): BigInt = initBigInt(value)

proc toCompressed*(po: Point): BigInt =
    ## get the compressed format of the point
    ## 
    ## TODO: implement this procedure
    return zerob

proc toUncompressed*(cur: Curve, po: Point): BigInt {.inline.} =
    ## get the uncompressed format of the point
    let nbits = cur.params.BitSize
    return (((0x04.initBigInt shl nbits) + po.x) shl nbits) + po.y

proc decomposite*(cur: Curve, po: BigInt): Point {.inline.} =
    ## decomposite the point
    let bs = cur.params.BitSize
    let msk = (oneb shl (bs + 1)) - oneb
    let highest = po shr (bs shl 1)
    if highest == 0x04.b:
        let y = po and msk
        let x = (po shr bs) and msk
        return Point(x: x, y: y)
    elif highest == zerob:
        let err = new LibraryError
        err.msg = "not implemented yet."
        raise err
    else:
        let err = new ValueError
        err.msg = "invalid point."
        raise err

template `mod`*(p: Point, m: BigInt): Point = Point(x: (p.x + m) mod m, y: (p.y + m) mod m)

proc addJacobian(cur: Curve, p1: Point, z1: BigInt, p2: Point, z2: BigInt): (Point, BigInt) {.inline.} =
    if z1 == zerob:
        return (p2, z2)

    if z2 == zerob:
        return (p1, z1)

    let z1z1 = z1 * z1
    let z2z2 = z2 * z2
    let u1 = p1.x * z2z2
    let u2 = p2.x * z1z1
    let s1 = p1.y * z2 * z2z2
    let s2 = p2.y * z1 * z1z1
    let h = (u2 - u1 + cur.params.P) mod cur.params.P
    let i = (h * h) shl 2
    let j = h * i
    let r = ((s2 - s1 + cur.params.P) mod cur.params.P) shl 1
    let v = u1 * i
    let x3 = r * r - j - v - v
    let y3 = r * (v - x3) - ((s1 * j) shl 1)
    let z3 = ((z1 + z2) * (z1 + z2) - z1z1 - z2z2) * h

    return (Point(x: x3, y: y3) mod cur.params.P, z3 mod cur.params.P)

proc doubledJacobian(cur: Curve, p1: Point, z1: BigInt): (Point, BigInt) {.inline.} =
    let a = p1.x * p1.x
    let b = p1.y * p1.y
    let c = powmod(p1.y, 4.b, cur.params.P)
    let d = (pow(p1.x + b, 2) - a - c) shl 1
    let e = a + a + a
    let f = e * e
    let x3 = f - d - d
    let y3 = e * (d - x3) - c * 8.b
    let z3 = p1.y * z1 * 2.b

    return (Point(x: x3, y: y3) mod cur.params.P, z3 mod cur.params.P)

proc jacobian2Affine(cur: Curve, p1: Point, z: BigInt): Point {.inline.} =
    if z == 0:
        return Point(x: zerob, y: zerob)

    let zinv = invMod(z, cur.params.P)
    let zinvsq = zinv * zinv

    return Point(x: p1.x * zinvsq, y: p1.y * zinv * zinvsq) mod cur.params.P

proc affineZ(p1: Point): BigInt {.inline.} = (if p1.x == zerob or p1.y == zerob: zerob else: oneb)

proc isOnCurve*(self: Curve, point: Point): bool =
    (
        pow(point.y, 2) - self.params.B - pow(point.x, 3)
    ) mod self.params.P == zerob

proc add*(self: Curve, p1: Point, p2: Point): Point =
    let res = addJacobian(self, p1, p1.affineZ(), p2, p2.affineZ())
    return jacobian2Affine(self, res[0], res[1])

proc double*(self: Curve, p: Point): Point {.inline.} =
    block:
        let (p, z) = doubledJacobian(self, p, p.affineZ())
        jacobian2Affine(self, p, z)

proc multiply*(self: Curve, p1: Point, n: BigInt): Point =
    if n == oneb:
        return p1

    if n == 2.b:
        return double(self, p1)

    if n == zerob:
        return Point(x: zerob, y: zerob)

    var rz = p1.affineZ()
    var pz = p1.affineZ()
    var rp = Point(x: zerob, y: zerob)

    var v = oneb
    while v < n:
        v = v shl 1

    while v > zerob:
        (rp, rz) = self.doubledJacobian(rp, rz)
        if (n and v) != zerob:
            (rp, rz) = self.addJacobian(rp, rz, p1, pz)
        v = v shr 1

    result = jacobian2Affine(self, rp, rz)

proc isInfinite*(po: Point): bool {.inline.} =
    return po.x == zerob or po.y == zerob

template `-`*(po: Point): Point = Point(x: po.x, y: -po.y)

template isFinite*(po: Point): bool =
    not po.isInfinite()

template multiplyBase*(self: Curve, n: BigInt): Point = multiply(self, self.params.G, n)
