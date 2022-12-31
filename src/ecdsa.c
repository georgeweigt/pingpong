// Elliptic curve digital signature algorithm

uint32_t *p256, *q256, *gx256, *gy256;
uint32_t *p384, *q384, *gx384, *gy384;

// secp256k1

#define P "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
#define Q "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
#define GX "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
#define GY "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"

void
ecdsa_init(void)
{
	p256 = ec_hexstr_to_bignum(P);
	q256 = ec_hexstr_to_bignum(Q);
	gx256 = ec_hexstr_to_bignum(GX);
	gy256 = ec_hexstr_to_bignum(GY);

	ec_malloc_count = 0;
}

// returns 0 for ok, -1 otherwise

int
ecdhe256_verify_hash(uint8_t *hash, int hashlen, uint8_t *rr, int r_length, uint8_t *ss, int s_length, uint8_t *xx, uint8_t *yy)
{
	int err;
	uint32_t *h, *r, *s, *x, *y;

	if (hashlen > 32)
		hashlen = 32;

	h = ec_buf_to_bignum(hash, hashlen);

	r = ec_buf_to_bignum(rr, r_length);
	s = ec_buf_to_bignum(ss, s_length);

	x = ec_buf_to_bignum(xx, 32);
	y = ec_buf_to_bignum(yy, 32);

	err = ecdsa256_verify_f(h, r, s, x, y);

	ec_free(h);
	ec_free(r);
	ec_free(s);
	ec_free(x);
	ec_free(y);

	return err;
}

// Returns 0 for ok, -1 otherwise
//
// All arguments are bignums
//
//	h	hash of certificate
//
//	r, s	signature
//
//	x, y	public key

int
ecdsa256_verify_f(uint32_t *h, uint32_t *r, uint32_t *s, uint32_t *x, uint32_t *y)
{
	int err;
	uint32_t *u, *v, *w;
	struct point R, S, T;

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	S.x = gx256;
	S.y = gy256;
	S.z = ec_int(1);

	T.x = x;
	T.y = y;
	T.z = ec_int(1);

	w = ec_modinv(s, q256);

	u = ec_mul(h, w);
	ec_mod(u, q256);

	v = ec_mul(r, w);
	ec_mod(v, q256);

	ec_twin_mult(&R, u, &S, v, &T, p256);

	ec_affinify(&R, p256);

	ec_mod(R.x, q256);

	if (ec_cmp(R.x, r) == 0)
		err = 0;
	else
		err = -1;

	ec_free_xyz(&R);

	ec_free(S.z);
	ec_free(T.z);
	ec_free(u);
	ec_free(v);
	ec_free(w);

	return err;
}

// returns 0 for ok, -1 otherwise

int
ecdhe384_verify_hash(uint8_t *hash, int hashlen, uint8_t *rr, int r_length, uint8_t *ss, int s_length, uint8_t *xx, uint8_t *yy)
{
	int err;
	uint32_t *h, *r, *s, *x, *y;

	if (hashlen > 48)
		hashlen = 48;

	h = ec_buf_to_bignum(hash, hashlen);

	r = ec_buf_to_bignum(rr, r_length);
	s = ec_buf_to_bignum(ss, s_length);

	x = ec_buf_to_bignum(xx, 48);
	y = ec_buf_to_bignum(yy, 48);

	err = ecdsa384_verify_f(h, r, s, x, y);

	ec_free(h);
	ec_free(r);
	ec_free(s);
	ec_free(x);
	ec_free(y);

	return err;
}

// Returns 0 for ok, -1 otherwise
//
// All arguments are bignums
//
//	h	hash of certificate
//
//	r, s	signature
//
//	x, y	public key

int
ecdsa384_verify_f(uint32_t *h, uint32_t *r, uint32_t *s, uint32_t *x, uint32_t *y)
{
	int err;
	uint32_t *u, *v, *w;
	struct point R, S, T;

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	S.x = gx384;
	S.y = gy384;
	S.z = ec_int(1);

	T.x = x;
	T.y = y;
	T.z = ec_int(1);

	w = ec_modinv(s, q384);

	u = ec_mul(h, w);
	ec_mod(u, q384);

	v = ec_mul(r, w);
	ec_mod(v, q384);

	ec_twin_mult(&R, u, &S, v, &T, p384);

	ec_affinify(&R, p384);

	ec_mod(R.x, q384);

	if (ec_cmp(R.x, r) == 0)
		err = 0;
	else
		err = -1;

	ec_free_xyz(&R);

	ec_free(S.z);
	ec_free(T.z);
	ec_free(u);
	ec_free(v);
	ec_free(w);

	return err;
}
