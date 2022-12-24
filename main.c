#include "defs.h"
#include "ec.c"

// Sepolia boot node geth

#define X "9246d00bc8fd1742e5ad2428b80fc4dc45d786283e05ef6edbd9002cbc335d40"
#define Y "998444732fbe921cb88e1d2c73d1b1de53bae6a2237996e9bfe14f871baf7066"

// secp256k1

#define P "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
#define Q "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
#define GX "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
#define GY "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"

uint32_t *bignum_x;
uint32_t *bignum_y;
uint32_t *bignum_p;
uint32_t *bignum_q;
uint32_t *bignum_gx;
uint32_t *bignum_gy;

int
main()
{
	bignum_x = ec_hexstr_to_bignum(X);
	bignum_y = ec_hexstr_to_bignum(Y);
	bignum_p = ec_hexstr_to_bignum(P);
	bignum_q = ec_hexstr_to_bignum(Q);
	bignum_gx = ec_hexstr_to_bignum(GX);
	bignum_gy = ec_hexstr_to_bignum(GY);
}
