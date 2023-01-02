void
ec_genkey(uint8_t *private_key, uint8_t *public_key_x, uint8_t *public_key_y)
{
	int i;
	uint32_t *d;
	struct point R, S;

	memset(private_key, 0, 32);
	memset(public_key_x, 0, 32);
	memset(public_key_y, 0, 32);

	R.x = gx256;
	R.y = gy256;
	R.z = ec_int(1);

	S.x = NULL;
	S.y = NULL;
	S.z = NULL;

	d = NULL;

	for (;;) {

		ec_free(d);
		d = ec_new(8);

		// generate private key d

		for (i = 0; i < 8; i++)
			d[i] = random();

		ec_norm(d);
		ec_mod(d, q256);

		if (ec_equal(d, 0))
			continue;

		// generate public key

		ec_mult(&S, d, &R, p256);

		if (ec_affinify(&S, p256) == 0)
			break;
	}

	// save private key

	for (i = 0; i < len(d); i++) {
		if (32 - 4 * i - 4 < 0)
			break; // err
		private_key[32 - 4 * i - 4] = d[i] >> 24;
		private_key[32 - 4 * i - 3] = d[i] >> 16;
		private_key[32 - 4 * i - 2] = d[i] >> 8;
		private_key[32 - 4 * i - 1] = d[i];
	}

	// save public keys

	for (i = 0; i < len(S.x); i++) {
		if (32 - 4 * i - 4 < 0)
			break; // err
		public_key_x[32 - 4 * i - 4] = S.x[i] >> 24;
		public_key_x[32 - 4 * i - 3] = S.x[i] >> 16;
		public_key_x[32 - 4 * i - 2] = S.x[i] >> 8;
		public_key_x[32 - 4 * i - 1] = S.x[i];
	}

	for (i = 0; i < len(S.y); i++) {
		if (32 - 4 * i - 4 < 0)
			break; // err
		public_key_y[32 - 4 * i - 4] = S.y[i] >> 24;
		public_key_y[32 - 4 * i - 3] = S.y[i] >> 16;
		public_key_y[32 - 4 * i - 2] = S.y[i] >> 8;
		public_key_y[32 - 4 * i - 1] = S.y[i];
	}

	ec_free(d);
	ec_free(R.z);
	ec_free_xyz(&S);
}

void
test_ec_genkey(void)
{
	int err, i;
	static uint8_t private_key[32], public_key_x[32], public_key_y[32];
	static uint8_t r[32], s[32], hash[32];

	printf("Testing ec_genkey ");

	ec_genkey(private_key, public_key_x, public_key_y);

#if 0
	printf("private key ");
	for (i = 0; i < 32; i++)
		printf("%02x", private_key[i]);
	printf("\n");

	printf("public key x ");
	for (i = 0; i < 32; i++)
		printf("%02x", public_key_x[i]);
	printf("\n");

	printf("public key y ");
	for (i = 0; i < 32; i++)
		printf("%02x", public_key_y[i]);
	printf("\n");
#endif

	for (i = 0; i < 32; i++)
		hash[i] = i;

	ec_sign(r, s, hash, private_key);

#if 0
	printf("r ");
	for (i = 0; i < 32; i++)
		printf("%02x", r[i]);
	printf("\n");

	printf("s ");
	for (i = 0; i < 32; i++)
		printf("%02x", s[i]);
	printf("\n");
#endif

	err = ec_verify(hash, r, s, public_key_x, public_key_y);

	printf("%s\n", err ? "err" : "ok");

	if (ec_malloc_count)
		printf("memory leak\n");
}
