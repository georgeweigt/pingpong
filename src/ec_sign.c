// sig		65 bytes (result r,s,v)
// hash		32 bytes (typically the sha256 of text or binary data)
// private_key	32 bytes

void
ec_sign(uint8_t *sig, uint8_t *hash, uint8_t *private_key)
{
	int i, v;
	uint32_t *d, *h, *k, *r, *s, *t, *u;
	struct point G, R;

	d = ec_buf_to_bignum(private_key, 32);
	h = ec_buf_to_bignum(hash, 32);

	G.x = gx256;
	G.y = gy256;
	G.z = ec_int(1);

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	for (;;) {

		k = ec_new(8);

		for (i = 0; i < 8; i++)
			k[i] = randf();

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

		// v = R.y mod 2

		v = R.y[0] & 1;

		// k = 1 / k

		t = ec_modinv(k, q256);
		ec_free(k);
		k = t;

		// s = k * (h + r * d) mod n

		t = ec_mul(r, d);
		ec_mod(t, q256);

		u = ec_add(h, t);
		ec_free(t);
		t = u;

		s = ec_mul(k, t);
		ec_free(t);

		ec_mod(s, q256);

		if (ec_equal(s, 0) || ec_cmp(s, lower_s) > 0) {
			ec_free(k);
			ec_free(r);
			ec_free(s);
			ec_free_xyz(&R);
			continue;
		}

		break; // success
	}

	memset(sig, 0, 64);

	for (i = 0; i < len(r) && i < 8; i++) {
		// bignums are LE, this converts to BE
		sig[32 - 4 * i - 4] = r[i] >> 24;
		sig[32 - 4 * i - 3] = r[i] >> 16;
		sig[32 - 4 * i - 2] = r[i] >> 8;
		sig[32 - 4 * i - 1] = r[i];
	}

	for (i = 0; i < len(s) && i < 8; i++) {
		// bignums are LE, this converts to BE
		sig[64 - 4 * i - 4] = s[i] >> 24;
		sig[64 - 4 * i - 3] = s[i] >> 16;
		sig[64 - 4 * i - 2] = s[i] >> 8;
		sig[64 - 4 * i - 1] = s[i];
	}

	sig[64] = v;

	ec_free(d);
	ec_free(h);
	ec_free(k);
	ec_free(r);
	ec_free(s);
	ec_free(G.z);
	ec_free_xyz(&R);
}
