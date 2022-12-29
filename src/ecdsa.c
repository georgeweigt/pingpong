#include "defs.h"

static uint32_t *p256, *q256, *gx256, *gy256;
static uint32_t *p384, *q384, *gx384, *gy384;

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

//	h	hash of certificate
//
//	d	private key
//
//	sig	pointer to 64-byte buffer

void
ecdsa256_sign_f(uint32_t *h, uint32_t *d, uint8_t *sig)
{
	int i;
	uint32_t *k, *r, *s, *t;
	struct point G, R;

	G.x = gx256;
	G.y = gy256;
	G.z = ec_int(1);

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	for (;;) {

		// choose k from [1, n - 1]

		k = ec_new(8);
		for (i = 0; i < 8; i++)
			k[i] = random();
		ec_norm(k);
		ec_mod(k, q256);
		if (ec_equal(k, 0)) {
			ec_free(k);
			continue;
		}

		// R = k * G

		ec_mult(&R, k, &G, p256);
		ec_affinify(&R, p256);

		// r = R.x mod n

		r = ec_dup(R.x);
		ec_mod(r, q256);

		if (ec_equal(r, 0)) {
			ec_free(k);
			ec_free(r);
			ec_free_xyz(&R);
			continue;
		}

		// k = 1 / k

		t = ec_modinv(k, q256);
		ec_free(k);
		k = t;

		// s = k * (h + r * d) mod n

		s = ec_mul(r, d);
		ec_mod(s, q256);

		t = ec_add(h, s);
		ec_free(s);
		s = t;
		ec_mod(s, q256);

		t = ec_mul(k, s);
		ec_free(s);
		s = t;
		ec_mod(s, q256);

		if (ec_equal(s, 0)) {
			ec_free(k);
			ec_free(r);
			ec_free(s);
			ec_free_xyz(&R);
			continue;
		}

		break;
	}

	// the signature is the pair (r, s)

	bzero(sig, 64);

	for (i = 0; i < len(r); i++) {
		sig[32 - 4 * i - 4] = r[i] >> 24;
		sig[32 - 4 * i - 3] = r[i] >> 16;
		sig[32 - 4 * i - 2] = r[i] >> 8;
		sig[32 - 4 * i - 1] = r[i];
	}

	for (i = 0; i < len(s); i++) {
		sig[64 - 4 * i - 4] = s[i] >> 24;
		sig[64 - 4 * i - 3] = s[i] >> 16;
		sig[64 - 4 * i - 2] = s[i] >> 8;
		sig[64 - 4 * i - 1] = s[i];
	}

	ec_free(k);
	ec_free(r);
	ec_free(s);

	ec_free(G.z);

	ec_free_xyz(&R);
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

//	h	hash of certificate
//
//	d	private key
//
//	sig	pointer to 96-byte buffer

void
ecdsa384_sign_f(uint32_t *h, uint32_t *d, uint8_t *sig)
{
	int i;
	uint32_t *k, *r, *s, *t;
	struct point G, R;

	G.x = gx384;
	G.y = gy384;
	G.z = ec_int(1);

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	for (;;) {

		// choose k from [1, n - 1]

		k = ec_new(12);
		for (i = 0; i < 12; i++)
			k[i] = random();
		ec_norm(k);
		ec_mod(k, q384);
		if (ec_equal(k, 0)) {
			ec_free(k);
			continue;
		}

		// R = k * G

		ec_mult(&R, k, &G, p384);
		ec_affinify(&R, p384);

		// r = R.x mod n

		r = ec_dup(R.x);
		ec_mod(r, q384);

		if (ec_equal(r, 0)) {
			ec_free(k);
			ec_free(r);
			ec_free_xyz(&R);
			continue;
		}

		// k = 1 / k

		t = ec_modinv(k, q384);
		ec_free(k);
		k = t;

		// s = k * (h + r * d) mod n

		s = ec_mul(r, d);
		ec_mod(s, q384);

		t = ec_add(h, s);
		ec_free(s);
		s = t;
		ec_mod(s, q384);

		t = ec_mul(k, s);
		ec_free(s);
		s = t;
		ec_mod(s, q384);

		if (ec_equal(s, 0)) {
			ec_free(k);
			ec_free(r);
			ec_free(s);
			ec_free_xyz(&R);
			continue;
		}

		break;
	}

	// the signature is the pair (r, s)

	bzero(sig, 96);

	for (i = 0; i < len(r); i++) {
		sig[48 - 4 * i - 4] = r[i] >> 24;
		sig[48 - 4 * i - 3] = r[i] >> 16;
		sig[48 - 4 * i - 2] = r[i] >> 8;
		sig[48 - 4 * i - 1] = r[i];
	}

	for (i = 0; i < len(s); i++) {
		sig[96 - 4 * i - 4] = s[i] >> 24;
		sig[96 - 4 * i - 3] = s[i] >> 16;
		sig[96 - 4 * i - 2] = s[i] >> 8;
		sig[96 - 4 * i - 1] = s[i];
	}

	ec_free(k);
	ec_free(r);
	ec_free(s);

	ec_free(G.z);

	ec_free_xyz(&R);
}

static char *str_p256 =
	"ffffffff00000001000000000000000000000000ffffffff"
	"ffffffffffffffff";

static char *str_q256 =
	"ffffffff00000000ffffffffffffffffbce6faada7179e84"
	"f3b9cac2fc632551";

static char *str_gx256 =
	"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0"
	"f4a13945d898c296";

static char *str_gy256 =
	"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ece"
	"cbb6406837bf51f5";

static char *str_p384 =
	"ffffffffffffffffffffffffffffffffffffffffffffffff"
	"fffffffffffffffeffffffff0000000000000000ffffffff";

static char *str_q384 =
	"ffffffffffffffffffffffffffffffffffffffffffffffff"
	"c7634d81f4372ddf581a0db248b0a77aecec196accc52973";

static char *str_gx384 =
	"aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b98"
	"59f741e082542a385502f25dbf55296c3a545e3872760ab7";

static char *str_gy384 =
	"3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147c"
	"e9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f";

void
ecdsa_init(void)
{
	p256 = ec_hexstr_to_bignum(str_p256);
	q256 = ec_hexstr_to_bignum(str_q256);
	gx256 = ec_hexstr_to_bignum(str_gx256);
	gy256 = ec_hexstr_to_bignum(str_gy256);

	p384 = ec_hexstr_to_bignum(str_p384);
	q384 = ec_hexstr_to_bignum(str_q384);
	gx384 = ec_hexstr_to_bignum(str_gx384);
	gy384 = ec_hexstr_to_bignum(str_gy384);
}
