void
generate_ephemeral_keyset(struct session *s)
{
	int err, i;
	uint32_t *d;
	struct point R, S;

	R.x = gx256;
	R.y = gy256;
	R.z = ec_int(1);

	S.x = NULL;
	S.y = NULL;
	S.z = NULL;

	d = NULL;

	do {
		ec_free(d);
		d = ec_new(8);

		// generate private key d

		for (i = 0; i < 8; i++)
			d[i] = random();

		ec_norm(d);
		ec_mod(d, q256);

		if (ec_equal(d, 0))
			continue;

		ec_mult(&S, d, &R, p256);
		err = ec_affinify(&S, p256);

	} while (err);

	// save private key

	memset(s->ephemeral_private_key, 0, 32);

	for (i = 0; i < len(d); i++) {
		if (32 - 4 * i - 4 < 0)
			break; // err
		s->ephemeral_private_key[32 - 4 * i - 4] = d[i] >> 24;
		s->ephemeral_private_key[32 - 4 * i - 3] = d[i] >> 16;
		s->ephemeral_private_key[32 - 4 * i - 2] = d[i] >> 8;
		s->ephemeral_private_key[32 - 4 * i - 1] = d[i];
	}

	// save public keys

	memset(s->ephemeral_public_key, 0, 64);

	for (i = 0; i < len(S.x); i++) {
		if (32 - 4 * i - 4 < 0)
			break; // err
		s->ephemeral_public_key[32 - 4 * i - 4] = S.x[i] >> 24;
		s->ephemeral_public_key[32 - 4 * i - 3] = S.x[i] >> 16;
		s->ephemeral_public_key[32 - 4 * i - 2] = S.x[i] >> 8;
		s->ephemeral_public_key[32 - 4 * i - 1] = S.x[i];
	}

	for (i = 0; i < len(S.y); i++) {
		if (32 - 4 * i - 4 < 0)
			break; // err
		s->ephemeral_public_key[64 - 4 * i - 4] = S.y[i] >> 24;
		s->ephemeral_public_key[64 - 4 * i - 3] = S.y[i] >> 16;
		s->ephemeral_public_key[64 - 4 * i - 2] = S.y[i] >> 8;
		s->ephemeral_public_key[64 - 4 * i - 1] = S.y[i];
	}

	// generate shared secret

	R.x = ec_buf_to_bignum(s->remote_public_key, 32);
	R.y = ec_buf_to_bignum(s->remote_public_key + 32, 32);

	ec_mult(&S, d, &R, p256);
	ec_affinify(&S, p256);

	for (i = 0; i < len(S.x); i++) {
		if (32 - 4 * i - 4 < 0)
			break; // err
		s->shared_secret[32 - 4 * i - 4] = S.x[i] >> 24;
		s->shared_secret[32 - 4 * i - 3] = S.x[i] >> 16;
		s->shared_secret[32 - 4 * i - 2] = S.x[i] >> 8;
		s->shared_secret[32 - 4 * i - 1] = S.x[i];
	}

	ec_free(d);
	ec_free_xyz(&R);
	ec_free_xyz(&S);
}
