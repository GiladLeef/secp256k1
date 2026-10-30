from setuptools import setup, Extension
import pybind11

ext_modules = [
    Extension(
        "secp256k1._bindings",
        sources=[
            "_bindings.cpp",
            "csrc/int.cpp",
            "csrc/intmod.cpp",
            "csrc/intgroup.cpp",
            "csrc/point.cpp",
            "csrc/secp256k1.cpp",
            "csrc/timer.cpp",
        ],
        include_dirs=[
            pybind11.get_include(),
            "csrc",
        ],
        language="c++",
        extra_compile_args=[
            "-std=gnu++23", "-O3", "-march=native", "-mtune=native",
            "-msse4.2", "-mavx2", "-ffast-math", "-funroll-loops",
            "-fomit-frame-pointer", "-Wno-write-strings", "-Wno-unused-result",
        ],
    ),
]

setup(
    name="secp256k1",
    version="0.1.0",
    packages=["secp256k1"],
    package_dir={"secp256k1": "."},
    ext_modules=ext_modules,
    install_requires=["pybind11"],
)
