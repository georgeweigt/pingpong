// hash, private_key --> ec_sign --> r, s

void
ec_sign(uint8_t *rbuf, uint8_t *sbuf, uint8_t *hash, uint8_t *private_key)
{
	int err, i;
	uint32_t *d, *h, *k, *r, *s, *t;
	struct point G, R;

	memset(rbuf, 0, 32);
	memset(sbuf, 0, 32);

	G.x = NULL;
	G.y = NULL;
	G.z = NULL;

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	k = NULL;
	r = NULL;
	s = NULL;

	d = ec_buf_to_bignum(private_key, 32);

	h = ec_buf_to_bignum(hash, 32);

	for (;;) {

		ec_free(k);
		ec_free(r);
		ec_free(s);

		k = ec_new(8);
		r = NULL;
		s = NULL;

		ec_free_xyz(&G);
		ec_free_xyz(&R);

		G.x = ec_dup(gx256);
		G.y = ec_dup(gy256);
		G.z = ec_int(1);

		// choose k from [1, n - 1]

		for (i = 0; i < 8; i++)
			k[i] = random();
		ec_norm(k);
		ec_mod(k, q256);
		if (ec_equal(k, 0))
			continue;

		// R = k * G

		ec_mult(&R, k, &G, p256);
		err = ec_affinify(&R, p256);

		if (err)
			continue;

		// r = R.x mod n

		r = ec_dup(R.x);
		ec_mod(r, q256);

		if (ec_equal(r, 0))
			continue;

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

		if (ec_equal(s, 0))
			continue;

		break;
	}

	for (i = 0; i < len(r); i++) {
		if (32 - 4 * i - 4 < 0)
			break; // err
		rbuf[32 - 4 * i - 4] = r[i] >> 24;
		rbuf[32 - 4 * i - 3] = r[i] >> 16;
		rbuf[32 - 4 * i - 2] = r[i] >> 8;
		rbuf[32 - 4 * i - 1] = r[i];
	}

	for (i = 0; i < len(s); i++) {
		if (32 - 4 * i - 4 < 0)
			break; // err
		sbuf[32 - 4 * i - 4] = s[i] >> 24;
		sbuf[32 - 4 * i - 3] = s[i] >> 16;
		sbuf[32 - 4 * i - 2] = s[i] >> 8;
		sbuf[32 - 4 * i - 1] = s[i];
	}

	ec_free(d);
	ec_free(h);
	ec_free(k);
	ec_free(r);
	ec_free(s);
	ec_free_xyz(&G);
	ec_free_xyz(&R);
}
