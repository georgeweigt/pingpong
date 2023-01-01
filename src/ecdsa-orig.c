// requires secp256r1

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
ecdsa256_verify_f(unsigned *h, unsigned *r, unsigned *s, unsigned *x, unsigned *y)
{
	int err;
	unsigned *u, *v, *w;
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

/* All arguments are bignums

	h	hash of certificate

	d	private key

	sig	pointer to 64-byte buffer
*/

void
ecdsa256_sign_f(unsigned *h, unsigned *d, unsigned char *sig)
{
	int i;
	unsigned *k, *r, *s, *t;
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

void
test_ecdsa256(void)
{
	unsigned *d, *h, *r, *s, *x, *y;
	unsigned char sig[64];

	// certificate's SHA1 hash

	char *str_h = "ce89669c8efcfe2c4f84e517339110908bb7303c";

	// private key

	char *str_d =
		"3C7AC4FE355588CE3D5B0A46A551371C"
		"2E2533093A710D3366432D597AAA5C27";

	// public key

	char *str_x =
		"EF7BA20E11D7EFBB6BDD9AA1AD3DB2"
		"8F8CFC1E7DD80EBDE3CA99343594EF31"
		"16";

	char *str_y =
		"26E6F34EB2139B6D550A919A373A17"
		"865792A479F56F09A6776F85939069A8"
		"C0";

	h = ec_hexstr_to_bignum(str_h);
	d = ec_hexstr_to_bignum(str_d);
	x = ec_hexstr_to_bignum(str_x);
	y = ec_hexstr_to_bignum(str_y);

	ecdsa256_sign_f(h, d, sig);

	r = ec_buf_to_bignum(sig, 32);
	s = ec_buf_to_bignum(sig + 32, 32);

	if (ecdsa256_verify_f(h, r, s, x, y) == 0)
		printf("ok: ec_test256\n");
	else
		printf("err: ec_test256\n");

	ec_free(h);
	ec_free(d);
	ec_free(r);
	ec_free(s);
	ec_free(x);
	ec_free(y);
}
