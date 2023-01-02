// Elliptic curve digital signature algorithm

uint32_t *p256, *q256, *gx256, *gy256;
uint32_t *p384, *q384, *gx384, *gy384;

#if 1

// secp256k1

#define P  "FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "FFFFFFFE" "FFFFFC2F"
#define Q  "FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "FFFFFFFE" "BAAEDCE6" "AF48A03B" "BFD25E8C" "D0364141"
#define GX "79BE667E" "F9DCBBAC" "55A06295" "CE870B07" "029BFCDB" "2DCE28D9" "59F2815B" "16F81798"
#define GY "483ADA77" "26A3C465" "5DA4FBFC" "0E1108A8" "FD17B448" "A6855419" "9C47D08F" "FB10D4B8"

#else

// secp256r1

#define P  "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
#define Q  "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
#define GX "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
#define GY "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"

#endif

void
ecdsa_init(void)
{
	p256 = ec_hexstr_to_bignum(P);
	q256 = ec_hexstr_to_bignum(Q);
	gx256 = ec_hexstr_to_bignum(GX);
	gy256 = ec_hexstr_to_bignum(GY);

	ec_malloc_count = 0;
}
