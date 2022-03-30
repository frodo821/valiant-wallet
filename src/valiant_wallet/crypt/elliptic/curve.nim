import bigints, strutils
export bigints, strutils

type
    Point* = object
        x*: BigInt
        y*: BigInt

    CurveParams* = object
        P*: BigInt
        N*: BigInt
        B*: BigInt
        G*: Point
        BitSize*: int64
        Name*: string

    Curve* = concept x
        x.params() is CurveParams

template `==`*(x: BigInt, y: int): bool = x == initBigInt(y)

template `==`*(p1: Point, p2: Point): bool = (p1.x == p2.x) and (p1.y == p2.y)

template b(value: int): BigInt = initBigInt(value)

proc toCompressed*(po: Point): BigInt =
    ## get the compressed format of the point
    ## 
    ## TODO: implement this procedure
    return 0.b

proc toUncompressed*(cur: Curve, po: Point): BigInt {.inline.} =
    ## get the uncompressed format of the point
    let nbits = cur.params.BitSize
    return (((0x04.initBigInt shl nbits) + po.x) shl nbits) + po.y

proc decomposite*(cur: Curve, po: BigInt): Point {.inline.} =
    ## decomposite the point
    let bs = cur.params.BitSize
    let msk = (1.b shl (bs + 1)) - 1.b
    let highest = po shr (bs shl 1)
    if highest == 0x04.b:
        let y = po and msk
        let x = (po shr bs) and msk
        return Point(x: x, y: y)
    elif highest == 0x00.b:
        let err = new LibraryError
        err.msg = "not implemented yet."
        raise err
    else:
        let err = new ValueError
        err.msg = "invalid point."
        raise err

template `mod`*(p: Point, m: BigInt): Point = Point(x: p.x mod m, y: p.y mod m)

proc addJacobian(cur: Curve, p1: Point, z1: BigInt, p2: Point, z2: BigInt): (Point, BigInt) {.inline.} =
    if z1 == 0.b:
        return (p2, z2)

    if z2 == 0.b:
        return (p1, z1)

    #[
        Z1Z1 = Z1^2
        Z2Z2 = Z2^2
        U1 = X1*Z2Z2
        U2 = X2*Z1Z1
        S1 = Y1*Z2*Z2Z2
        S2 = Y2*Z1*Z1Z1
        H = U2-U1
        I = (2*H)^2
        J = H*I
        r = 2*(S2-S1)
        V = U1*I
        X3 = r^2-J-2*V
        Y3 = r*(V-X3)-2*S1*J
        Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2)*H
    ]#

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
        return Point(x: 0.b, y: 0.b)

    let zinv = invMod(z, cur.params.P)
    let zinvsq = zinv * zinv

    return Point(x: p1.x * zinvsq, y: p1.y * zinv * zinvsq) mod cur.params.P

proc affineZ(p1: Point): BigInt {.inline.} = (if p1.x == 0.b or p1.y == 0.b: 0.b else: 1.b)

proc isOnCurve*(self: Curve, point: Point): bool =
    (
        pow(point.y, 2) - self.params.B - pow(point.x, 3)
    ) mod self.params.P == 0.b

proc add*(self: Curve, p1: Point, p2: Point): Point =
    let res = addJacobian(self, p1, p1.affineZ(), p2, p2.affineZ())
    return jacobian2Affine(self, res[0], res[1])

proc double*(self: Curve, p: Point): Point {.inline.} =
    block:
        let (p, z) = doubledJacobian(self, p, p.affineZ())
        jacobian2Affine(self, p, z)

proc multiply*(self: Curve, p1: Point, n: BigInt): Point =
    if n == 1.b:
        return p1

    if n == 2.b:
        return double(self, p1)

    if n == 0.b:
        return Point(x: 0.b, y: 0.b)

    var rz = p1.affineZ()
    var pz = p1.affineZ()
    var rp = Point(x: 0.b, y: 0.b)

    var v = 1.b
    while v < n:
        v = v shl 1

    while v > 0.b:
        (rp, rz) = self.doubledJacobian(rp, rz)
        if (n and v) != 0.b:
            (rp, rz) = self.addJacobian(rp, rz, p1, pz)
        v = v shr 1

    result = jacobian2Affine(self, rp, rz)

proc isInfinite*(po: Point): bool {.inline.} =
    return po.x == 0.b or po.y == 0.b

template isFinite*(po: Point): bool =
    not po.isInfinite()

template multiplyBase*(self: Curve, n: BigInt): Point = multiply(self, self.params.G, n)
