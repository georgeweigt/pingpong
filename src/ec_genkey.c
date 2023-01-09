// private_key	32 bytes (result)
// public_key	64 bytes (result)

void
ec_genkey(uint8_t *private_key, uint8_t *public_key)
{
	int i;
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

	} while (ec_equal(d, 0));

	// generate public key

	ec_mult(&S, d, &R, p256);
	ec_affinify(&S, p256);

	// save private key

	memset(private_key, 0, 32);

	for (i = 0; i < len(d); i++) {
		if (32 - 4 * i - 4 < 0)
			break; // err, result greater than 32 bytes
		// bignums are LE, this converts to BE
		private_key[32 - 4 * i - 4] = d[i] >> 24;
		private_key[32 - 4 * i - 3] = d[i] >> 16;
		private_key[32 - 4 * i - 2] = d[i] >> 8;
		private_key[32 - 4 * i - 1] = d[i];
	}

	// save public key

	memset(public_key, 0, 64);

	for (i = 0; i < len(S.x); i++) {
		if (32 - 4 * i - 4 < 0)
			break; // err, result greater than 32 bytes
		// bignums are LE, this converts to BE
		public_key[32 - 4 * i - 4] = S.x[i] >> 24;
		public_key[32 - 4 * i - 3] = S.x[i] >> 16;
		public_key[32 - 4 * i - 2] = S.x[i] >> 8;
		public_key[32 - 4 * i - 1] = S.x[i];
	}

	for (i = 0; i < len(S.y); i++) {
		if (32 - 4 * i - 4 < 0)
			break; // err, result greater than 32 bytes
		// bignums are LE, this converts to BE
		public_key[64 - 4 * i - 4] = S.y[i] >> 24;
		public_key[64 - 4 * i - 3] = S.y[i] >> 16;
		public_key[64 - 4 * i - 2] = S.y[i] >> 8;
		public_key[64 - 4 * i - 1] = S.y[i];
	}

	ec_free(d);
	ec_free(R.z);
	ec_free_xyz(&S);
}
