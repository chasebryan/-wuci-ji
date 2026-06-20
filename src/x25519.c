#include <stdint.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef __uint128_t u128;

#define FE_MASK ((u64)((1ULL << 51) - 1))

typedef u64 fe[5];

static u64 load64_le(const u8 *p) {
    return ((u64)p[0]) |
           ((u64)p[1] << 8) |
           ((u64)p[2] << 16) |
           ((u64)p[3] << 24) |
           ((u64)p[4] << 32) |
           ((u64)p[5] << 40) |
           ((u64)p[6] << 48) |
           ((u64)p[7] << 56);
}

static void store64_le(u8 *p, u64 v) {
    for (unsigned i = 0; i < 8; i++) {
        p[i] = (u8)(v >> (8 * i));
    }
}

static void fe_copy(fe out, const fe in) {
    for (unsigned i = 0; i < 5; i++) {
        out[i] = in[i];
    }
}

static void fe_0(fe out) {
    for (unsigned i = 0; i < 5; i++) {
        out[i] = 0;
    }
}

static void fe_1(fe out) {
    fe_0(out);
    out[0] = 1;
}

static void fe_carry(fe h) {
    for (unsigned pass = 0; pass < 2; pass++) {
        u64 c;
        c = h[0] >> 51; h[0] &= FE_MASK; h[1] += c;
        c = h[1] >> 51; h[1] &= FE_MASK; h[2] += c;
        c = h[2] >> 51; h[2] &= FE_MASK; h[3] += c;
        c = h[3] >> 51; h[3] &= FE_MASK; h[4] += c;
        c = h[4] >> 51; h[4] &= FE_MASK; h[0] += c * 19;
    }
    u64 c = h[0] >> 51;
    h[0] &= FE_MASK;
    h[1] += c;
}

static void fe_frombytes(fe out, const u8 in[32]) {
    out[0] = load64_le(in + 0) & FE_MASK;
    out[1] = (load64_le(in + 6) >> 3) & FE_MASK;
    out[2] = (load64_le(in + 12) >> 6) & FE_MASK;
    out[3] = (load64_le(in + 19) >> 1) & FE_MASK;
    out[4] = (load64_le(in + 24) >> 12) & FE_MASK;
}

static void fe_tobytes(u8 out[32], const fe in) {
    fe h;
    fe_copy(h, in);
    fe_carry(h);

    u64 q = (h[0] + 19) >> 51;
    q = (h[1] + q) >> 51;
    q = (h[2] + q) >> 51;
    q = (h[3] + q) >> 51;
    q = (h[4] + q) >> 51;
    h[0] += 19 * q;
    fe_carry(h);

    store64_le(out + 0, h[0] | (h[1] << 51));
    store64_le(out + 8, (h[1] >> 13) | (h[2] << 38));
    store64_le(out + 16, (h[2] >> 26) | (h[3] << 25));
    store64_le(out + 24, (h[3] >> 39) | (h[4] << 12));
}

static void fe_add(fe out, const fe a, const fe b) {
    for (unsigned i = 0; i < 5; i++) {
        out[i] = a[i] + b[i];
    }
    fe_carry(out);
}

static void fe_sub(fe out, const fe a, const fe b) {
    static const u64 four_p[5] = {
        ((u64)1 << 53) - 76,
        ((u64)1 << 53) - 4,
        ((u64)1 << 53) - 4,
        ((u64)1 << 53) - 4,
        ((u64)1 << 53) - 4,
    };
    for (unsigned i = 0; i < 5; i++) {
        out[i] = a[i] + four_p[i] - b[i];
    }
    fe_carry(out);
}

static void fe_reduce128(fe out, u128 c0, u128 c1, u128 c2, u128 c3, u128 c4) {
    u64 h0, h1, h2, h3, h4;

    c1 += c0 >> 51; h0 = (u64)c0 & FE_MASK;
    c2 += c1 >> 51; h1 = (u64)c1 & FE_MASK;
    c3 += c2 >> 51; h2 = (u64)c2 & FE_MASK;
    c4 += c3 >> 51; h3 = (u64)c3 & FE_MASK;
    h4 = (u64)c4 & FE_MASK;
    h0 += (u64)(c4 >> 51) * 19;

    out[0] = h0;
    out[1] = h1;
    out[2] = h2;
    out[3] = h3;
    out[4] = h4;
    fe_carry(out);
}

static void fe_mul(fe out, const fe a, const fe b) {
    u128 c0 = (u128)a[0] * b[0]
            + (u128)19 * ((u128)a[1] * b[4] + (u128)a[2] * b[3]
            + (u128)a[3] * b[2] + (u128)a[4] * b[1]);
    u128 c1 = (u128)a[0] * b[1] + (u128)a[1] * b[0]
            + (u128)19 * ((u128)a[2] * b[4] + (u128)a[3] * b[3]
            + (u128)a[4] * b[2]);
    u128 c2 = (u128)a[0] * b[2] + (u128)a[1] * b[1] + (u128)a[2] * b[0]
            + (u128)19 * ((u128)a[3] * b[4] + (u128)a[4] * b[3]);
    u128 c3 = (u128)a[0] * b[3] + (u128)a[1] * b[2]
            + (u128)a[2] * b[1] + (u128)a[3] * b[0]
            + (u128)19 * ((u128)a[4] * b[4]);
    u128 c4 = (u128)a[0] * b[4] + (u128)a[1] * b[3]
            + (u128)a[2] * b[2] + (u128)a[3] * b[1]
            + (u128)a[4] * b[0];
    fe_reduce128(out, c0, c1, c2, c3, c4);
}

static void fe_sq(fe out, const fe a) {
    fe_mul(out, a, a);
}

static void fe_mul121666(fe out, const fe a) {
    fe_reduce128(out,
        (u128)a[0] * 121666,
        (u128)a[1] * 121666,
        (u128)a[2] * 121666,
        (u128)a[3] * 121666,
        (u128)a[4] * 121666);
}

static void fe_cswap(fe a, fe b, u64 swap) {
    u64 mask = 0 - swap;
    for (unsigned i = 0; i < 5; i++) {
        u64 t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

static int point_has_small_order(const u8 point[32]) {
    static const u8 blocklist[7][32] = {
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae,
         0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
         0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd,
         0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00},
        {0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24,
         0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
         0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86,
         0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57},
        {0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
        {0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
        {0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
    };
    u8 c[7] = {0};
    for (unsigned j = 0; j < 31; j++) {
        for (unsigned i = 0; i < 7; i++) {
            c[i] |= point[j] ^ blocklist[i][j];
        }
    }
    for (unsigned i = 0; i < 7; i++) {
        c[i] |= (point[31] & 0x7f) ^ blocklist[i][31];
    }

    u32 k = 0;
    for (unsigned i = 0; i < 7; i++) {
        k |= (u32)(c[i] - 1);
    }
    return (int)((k >> 8) & 1);
}

static int exponent_bit(unsigned bit) {
    static const u8 exp[32] = {
        0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    };
    return (exp[bit >> 3] >> (bit & 7)) & 1;
}

static void fe_invert(fe out, const fe z) {
    fe result, base, tmp;
    fe_1(result);
    fe_copy(base, z);

    for (int bit = 254; bit >= 0; bit--) {
        fe_sq(tmp, result);
        fe_copy(result, tmp);
        if (exponent_bit((unsigned)bit)) {
            fe_mul(tmp, result, base);
            fe_copy(result, tmp);
        }
    }
    fe_copy(out, result);
}

int x25519_scalar_mult(u8 out[32], const u8 scalar[32], const u8 point[32]) {
    if (point_has_small_order(point)) {
        return 0;
    }

    u8 e[32];
    for (unsigned i = 0; i < 32; i++) {
        e[i] = scalar[i];
    }
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;

    fe x1, x2, z2, x3, z3, a, b, aa, bb, e_fe, c, d, da, cb, tmp0, tmp1;
    fe_frombytes(x1, point);
    fe_1(x2);
    fe_0(z2);
    fe_copy(x3, x1);
    fe_1(z3);

    u64 swap = 0;
    for (int pos = 254; pos >= 0; pos--) {
        u64 bit = (e[pos >> 3] >> (pos & 7)) & 1;
        swap ^= bit;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = bit;

        fe_add(a, x2, z2);
        fe_sq(aa, a);
        fe_sub(b, x2, z2);
        fe_sq(bb, b);
        fe_sub(e_fe, aa, bb);
        fe_add(c, x3, z3);
        fe_sub(d, x3, z3);
        fe_mul(da, d, a);
        fe_mul(cb, c, b);

        fe_add(tmp0, da, cb);
        fe_sq(x3, tmp0);
        fe_sub(tmp0, da, cb);
        fe_sq(tmp1, tmp0);
        fe_mul(z3, tmp1, x1);
        fe_mul(x2, aa, bb);
        fe_mul121666(tmp0, e_fe);
        fe_add(tmp1, aa, tmp0);
        fe_mul(z2, e_fe, tmp1);
    }

    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);
    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(out, x2);

    u8 any = 0;
    for (unsigned i = 0; i < 32; i++) {
        any |= out[i];
    }
    return any != 0;
}

int x25519_basepoint(u8 out[32], const u8 scalar[32]) {
    static const u8 basepoint[32] = {9};
    return x25519_scalar_mult(out, scalar, basepoint);
}
