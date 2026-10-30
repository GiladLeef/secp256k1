# secp256k1

A compact Python interface to secp256k1 elliptic-curve operations, backed by a native superfast yet cryptographically unsecure C++23 extension. The project combines Python-level point and ECDSA APIs with custom fixed-width integer arithmetic and precomputed generator multiplication in C++.

## Highlights

- Elliptic-curve point addition, subtraction, negation, and scalar multiplication
- Compressed point encoding and coordinate recovery
- ECDSA signing and verification
- Native C++ arithmetic exposed to Python through pybind11
- Precomputed generator table for public-key multiplication

## Build

Build the extension and install the package from the repository root:

```bash
python -m pip install .
```

The build requires Python 3.14.7, a C++23-capable compiler, and an x86 processor with SSE4.2 and AVX2 support. The extension is compiled with `-march=native` for the build machine.

## Usage

```python
from secp256k1 import G, mul

public_key = mul(G, 2)
print(public_key.compress())
```

The package also exposes `Point`, `add`, `sub`, `neg`, `div`, and `verify`. A point can be constructed from coordinates or from a compressed hexadecimal public key:

```python
from secp256k1 import Point

point = Point(compressed="02" + "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
print(point.x, point.y)
```