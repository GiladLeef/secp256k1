import hashlib
import random
from . import _bindings

__version__ = "0.1.0"

_bindings.init()

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
a = 0
b = 7

Gx = _bindings.g_x()
Gy = _bindings.g_y()

l1 = 37718080363155996902926221483475020450927657555482586988616620542887997980018
l2 = 78074008874160198520644763525212887401909906723592317393988542598630163514318

b1 = 55594575648329892869085402983802832744385952214688224221778511981742606582254
b2 = 60197513588986302554485582024885075108884032450952339817679072026166228089408

class Point:
    def __init__(self, x=None, y=None, compressed=None):
        if compressed is not None:
            self.x, self.y = self.decompress(compressed)
        else:
            self.x = x
            self.y = y

    def __repr__(self):
        return self.compress()

    def compress(self):
        prefix = '02' if self.y % 2 == 0 else '03'
        return prefix + hex(self.x)[2:].zfill(64)

    @staticmethod
    def decompress(compressed):
        prefix = compressed[:2]
        x = int(compressed[2:], 16)
        y = _bindings.get_y_from_x(x, prefix == '02')
        return x, y

    def __eq__(self, other):
        if isinstance(other, Point):
            return (self.x, self.y) == (other.x, other.y)
        return False

    def __add__(self, other):
        return add(self, other)

    def __sub__(self, other):
        return sub(self, other)

    def __mul__(self, scalar):
        return mul(self, scalar)

    def __truediv__(self, scalar):
        return div(self, scalar)

    def __neg__(self):
        return neg(self)

    def slope(self, other=None):
        if other is None:
            other = G
        if isinstance(other, int):
            other = mul(G, other)
        return _bindings.compute_slope(self.x, self.y, other.x, other.y)

    @staticmethod
    def hash(message):
        return int(hashlib.sha256(message.encode()).hexdigest(), 16)

    def sign(self, message, private_key):
        z = self.hash(message) % N
        while True:
            k = random.randint(1, N)
            rx, ry = _bindings.mul_by_g(k)
            r = rx % N
            if r == 0:
                continue
            s = ((z + r * private_key) * pow(k, -1, N)) % N
            if s == 0:
                continue
            return r, s, z

G = Point(x=Gx, y=Gy)


def modInv(a, m):
    return pow(a, -1, m)


def add(P, Q):
    if isinstance(P, str):
        P = Point(compressed=P)
    if isinstance(Q, int):
        Q = mul(G, Q)
    if P is None or (P.x is None and P.y is None):
        return Q
    if Q is None or (Q.x is None and Q.y is None):
        return P
    result = _bindings.add_points(P.x, P.y, Q.x, Q.y)
    if result is None:
        return None
    rx, ry = result
    return Point(rx, ry)


def mul(K, scalar):
    if isinstance(K, str):
        K = Point(compressed=K)
    scalar = scalar % N
    if scalar == 0:
        return None
    result = _bindings.mul_point(K.x, K.y, scalar)
    if result is None:
        return None
    rx, ry = result
    return Point(rx, ry)


def div(K, scalar):
    return mul(K, modInv(scalar, N))


def sub(P, Q):
    if isinstance(P, str):
        P = Point(compressed=P)
    if isinstance(Q, int):
        Q = mul(G, Q)
    return add(P, neg(Q))


def neg(P):
    return Point(P.x, (-P.y) % p)


def verify(message, signature, pubkey):
    r, s = signature
    if not (1 <= r < N and 1 <= s < N):
        return False
    z = Point.hash(message) % N
    w = pow(s, -1, N)
    u1 = (z * w) % N
    u2 = (r * w) % N
    R = add(mul(G, u1), mul(pubkey, u2))
    return R is not None and R.x % N == r
