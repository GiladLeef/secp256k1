#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <mutex>
#include "secp256k1.h"

namespace py = pybind11;

static Secp256K1 *g_ctx = nullptr;
static bool g_initialized = false;
static std::mutex g_mutex;

static void ensure_init() {
    if (!g_initialized) {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_initialized) {
            g_ctx = new Secp256K1();
            g_ctx->Init();
            g_initialized = true;
        }
    }
}

static void set_int_from_py(Int &dst, const py::int_ &src) {
    std::string s = py::str(py::module_::import("builtins").attr("hex")(src));
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        s = s.substr(2);
    if (s.empty()) s = "0";
    if (s.size() % 2) s = "0" + s;
    dst.SetBase16(s.c_str());
}

static py::int_ get_int_from_py(Int &src) {
    std::string hex_str = src.GetBase16();
    py::object builtins = py::module_::import("builtins");
    return builtins.attr("int")(py::str(hex_str), 16);
}

static py::object add_points(const py::int_ &px, const py::int_ &py_,
                              const py::int_ &qx, const py::int_ &qy_) {
    ensure_init();
    Int pxi, pyi, qxi, qyi;
    set_int_from_py(pxi, px);
    set_int_from_py(pyi, py_);
    set_int_from_py(qxi, qx);
    set_int_from_py(qyi, qy_);

    if (pxi.IsZero() && pyi.IsZero())
        return py::make_tuple(qx, qy_);
    if (qxi.IsZero() && qyi.IsZero())
        return py::make_tuple(px, py_);

    if (pxi.IsEqual(&qxi)) {
        Int neg_y;
        neg_y.Set(&pyi);
        neg_y.ModNeg();
        if (neg_y.IsEqual(&qyi))
            return py::none();
    }

    Point p1, p2;
    p1.x.Set(&pxi); p1.y.Set(&pyi); p1.z.SetInt32(1);
    p2.x.Set(&qxi); p2.y.Set(&qyi); p2.z.SetInt32(1);

    Point r;
    if (pxi.IsEqual(&qxi) && pyi.IsEqual(&qyi))
        r = g_ctx->DoubleDirect(p1);
    else
        r = g_ctx->AddDirect(p1, p2);

    return py::make_tuple(get_int_from_py(r.x), get_int_from_py(r.y));
}

static py::object double_point(const py::int_ &px, const py::int_ &py_) {
    ensure_init();
    Int pxi, pyi;
    set_int_from_py(pxi, px);
    set_int_from_py(pyi, py_);
    Point p;
    p.x.Set(&pxi); p.y.Set(&pyi); p.z.SetInt32(1);
    Point r = g_ctx->DoubleDirect(p);
    return py::make_tuple(get_int_from_py(r.x), get_int_from_py(r.y));
}

static py::object mul_point(const py::int_ &px, const py::int_ &py_,
                             const py::int_ &scalar) {
    ensure_init();
    Int pxi, pyi, sc;
    set_int_from_py(pxi, px);
    set_int_from_py(pyi, py_);
    set_int_from_py(sc, scalar);

    Point P;
    P.x.Set(&pxi); P.y.Set(&pyi); P.z.SetInt32(1);

    Point result;
    result.Clear();

    while (!sc.IsZero()) {
        if (sc.IsOdd()) {
            if (result.x.IsZero() && result.y.IsZero()) {
                result.x.Set(&P.x); result.y.Set(&P.y); result.z.SetInt32(1);
            } else {
                result = g_ctx->AddDirect(result, P);
            }
        }
        P = g_ctx->DoubleDirect(P);
        sc.ShiftR(1);
    }

    if (result.x.IsZero() && result.y.IsZero())
        return py::none();

    return py::make_tuple(get_int_from_py(result.x), get_int_from_py(result.y));
}

static py::object mul_by_g(const py::int_ &scalar) {
    ensure_init();
    Int sc;
    set_int_from_py(sc, scalar);
    Point r = g_ctx->ComputePublicKey(&sc, true);
    return py::make_tuple(get_int_from_py(r.x), get_int_from_py(r.y));
}

static py::int_ get_y_from_x(const py::int_ &x, bool is_even) {
    ensure_init();
    Int xi, s, p;
    set_int_from_py(xi, x);
    s.ModSquareK1(&xi);
    p.ModMulK1(&s, &xi);
    p.ModAdd(7);
    p.ModSqrt();
    if (p.IsEven() != is_even)
        p.ModNeg();
    return get_int_from_py(p);
}

static bool is_on_curve(const py::int_ &x, const py::int_ &y) {
    ensure_init();
    Int xi, yi;
    set_int_from_py(xi, x);
    set_int_from_py(yi, y);
    Point p;
    p.x.Set(&xi); p.y.Set(&yi); p.z.SetInt32(1);
    return g_ctx->EC(p);
}

static py::int_ mod_inv_p(const py::int_ &a) {
    ensure_init();
    Int ai;
    set_int_from_py(ai, a);
    ai.ModInv();
    return get_int_from_py(ai);
}

static py::int_ mod_sqrt_p(const py::int_ &a) {
    ensure_init();
    Int ai;
    set_int_from_py(ai, a);
    ai.ModSqrt();
    return get_int_from_py(ai);
}

static py::int_ mod_neg_p(const py::int_ &a) {
    ensure_init();
    Int ai;
    set_int_from_py(ai, a);
    ai.ModNeg();
    return get_int_from_py(ai);
}

static py::int_ get_g_x() {
    ensure_init();
    return get_int_from_py(g_ctx->G.x);
}

static py::int_ get_g_y() {
    ensure_init();
    return get_int_from_py(g_ctx->G.y);
}

static py::int_ get_order() {
    ensure_init();
    return get_int_from_py(g_ctx->order);
}

static py::int_ compute_slope(const py::int_ &px, const py::int_ &py_,
                               const py::int_ &qx, const py::int_ &qy_) {
    ensure_init();
    Int pxi, pyi, qxi, qyi;
    set_int_from_py(pxi, px);
    set_int_from_py(pyi, py_);
    set_int_from_py(qxi, qx);
    set_int_from_py(qyi, qy_);

    Point p;
    p.x.Set(&pxi); p.y.Set(&pyi); p.z.SetInt32(1);

    Point q;
    q.x.Set(&qxi); q.y.Set(&qyi); q.z.SetInt32(1);

    Int s = g_ctx->Slope(p, q);
    return get_int_from_py(s);
}

PYBIND11_MODULE(_bindings, m) {
    m.doc() = "secp256k1 math bindings (kangaroo C++ backend)";

    m.def("init", &ensure_init, "Initialize the secp256k1 curve context");
    m.def("add_points", &add_points, "Add two affine points on secp256k1");
    m.def("double_point", &double_point, "Double an affine point on secp256k1");
    m.def("mul_point", &mul_point, "Multiply a point by a scalar (double-and-add)");
    m.def("mul_by_g", &mul_by_g, "Multiply the generator by a scalar (uses precomputed table)");
    m.def("get_y_from_x", &get_y_from_x, "Recover Y coordinate from X given parity");
    m.def("is_on_curve", &is_on_curve, "Check if (x,y) is on the secp256k1 curve");
    m.def("mod_inv_p", &mod_inv_p, "Modular inverse modulo the secp256k1 field prime p");
    m.def("mod_sqrt_p", &mod_sqrt_p, "Modular square root modulo p");
    m.def("mod_neg_p", &mod_neg_p, "Modular negation modulo p");
    m.def("g_x", &get_g_x, "Generator x coordinate");
    m.def("g_y", &get_g_y, "Generator y coordinate");
    m.def("order", &get_order, "Curve order N");
    m.def("compute_slope", &compute_slope, "Compute slope between two affine points");
}
