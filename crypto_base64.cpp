
static void CRYPTO_BASE64_Encode_internal(unsigned char *dst,  size_t *dst_len, unsigned char *src, size_t src_len, const unsigned char *basis, unsigned int padding);
static int CRYPTO_BASE64_Decode_internal(unsigned char *dst,  size_t *dst_len, unsigned char *src, size_t src_len, const unsigned char *basis);


void CRYPTO_BASE64_Encode(unsigned char *dst,  size_t *dst_len, unsigned char *src, size_t src_len)
{
    static unsigned char   basis64[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    CRYPTO_BASE64_Encode_internal(dst, dst_len, src, src_len, basis64, 1);
}


void CRYPTO_BASE64URL_Encode(unsigned char *dst,  size_t *dst_len, unsigned char *src, size_t src_len)
{
    static unsigned char   basis64[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    CRYPTO_BASE64_Encode_internal(dst, dst_len, src, src_len, basis64, 0);
}


static void CRYPTO_BASE64_Encode_internal(unsigned char *dst,  size_t *dst_len, unsigned char *src, size_t src_len, const unsigned char *basis,
    unsigned int padding)
{
    unsigned char         *d, *s;
    size_t          len;

    len = src_len;
    s = src;
    d = dst;

    while (len > 2) {
        *d++ = basis[(s[0] >> 2) & 0x3f];
        *d++ = basis[((s[0] & 3) << 4) | (s[1] >> 4)];
        *d++ = basis[((s[1] & 0x0f) << 2) | (s[2] >> 6)];
        *d++ = basis[s[2] & 0x3f];

        s += 3;
        len -= 3;
    }

    if (len) {
        *d++ = basis[(s[0] >> 2) & 0x3f];

        if (len == 1) {
            *d++ = basis[(s[0] & 3) << 4];
            if (padding) {
                *d++ = '=';
            }

        } else {
            *d++ = basis[((s[0] & 3) << 4) | (s[1] >> 4)];
            *d++ = basis[(s[1] & 0x0f) << 2];
        }

        if (padding) {
            *d++ = '=';
        }
    }

    *dst_len = d - dst;
}


int CRYPTO_BASE64_Decode(unsigned char *dst,  size_t *dst_len, unsigned char *src, size_t src_len)
{
    static unsigned char   basis64[] = {
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 62, 77, 77, 77, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 77, 77, 77, 77, 77, 77,
        77,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 77, 77, 77, 77, 77,
        77, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 77, 77, 77, 77, 77,

        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77
    };

    return CRYPTO_BASE64_Decode_internal(dst, dst_len, src, src_len, basis64);
}


int CRYPTO_BASE64URL_Decode(unsigned char *dst,  size_t *dst_len, unsigned char *src, size_t src_len)
{
    static unsigned char   basis64[] = {
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 62, 77, 77,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 77, 77, 77, 77, 77, 77,
        77,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 77, 77, 77, 77, 63,
        77, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 77, 77, 77, 77, 77,

        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
        77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77
    };

    return CRYPTO_BASE64_Decode_internal(dst, dst_len, src, src_len, basis64);
}


static int CRYPTO_BASE64_Decode_internal(unsigned char *dst,  size_t *dst_len, unsigned char *src, size_t src_len, const unsigned char *basis)
{
    size_t          len;
    unsigned char         *d, *s;

    for (len = 0; len < src_len; len++) {
        if (src[len] == '=') {
            break;
        }

        if (basis[src[len]] == 77) {
            return -1;
        }
    }

    if (len % 4 == 1) {
        return -1;
    }

    s = src;
    d = dst;

    while (len > 3) {
        *d++ = (unsigned char) (basis[s[0]] << 2 | basis[s[1]] >> 4);
        *d++ = (unsigned char) (basis[s[1]] << 4 | basis[s[2]] >> 2);
        *d++ = (unsigned char) (basis[s[2]] << 6 | basis[s[3]]);

        s += 4;
        len -= 4;
    }

    if (len > 1) {
        *d++ = (unsigned char) (basis[s[0]] << 2 | basis[s[1]] >> 4);
    }

    if (len > 2) {
        *d++ = (unsigned char) (basis[s[1]] << 4 | basis[s[2]] >> 2);
    }

    *dst_len = d - dst;

    return 0;
}

