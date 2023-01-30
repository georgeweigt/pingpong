// deterministic signature per RFC 6979

// sig		65 bytes (result r,s,v)
// hash		32 bytes (typically the sha256 of text or binary data)
// private_key	32 bytes

void
ec_sign_rfc6979(uint8_t *sig, uint8_t *hash, uint8_t *private_key)
{
	int i, v;
	uint8_t h1[32], V[97], K[32];
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

	// see RFC 6979 section 3.2

	// a. h1 = H(m)

	sha256(hash, 32, h1); // hash == m

	// b. V = 0x01 0x01 0x01 ... 0x01

	memset(V, 0x01, 32);

	// c. K = 0x00 0x00 0x00 ... 0x00

	memset(K, 0x00, 32);

	// d. K = HMAC_K(V || 0x00 || x || h1)

	V[32] = 0x00;

	memcpy(V + 33, private_key, 32); // private_key == x
	memcpy(V + 65, h1, 32);

	hmac_sha256(K, 32, V, 97, K);

	// e. V = HMAC_K(V)

	hmac_sha256(K, 32, V, 32, V);

	// f. K = HMAC_K(V || 0x01 || x || h1)

	V[32] = 0x01;

	hmac_sha256(K, 32, V, 97, K);

	// g. V = HMAC_K(V)

	hmac_sha256(K, 32, V, 32, V);

	// h.

	V[32] = 0x00;

	for (;;) { // loop until return r,s,v

		// V = HMAC_K(V)

		hmac_sha256(K, 32, V, 32, V);

		// for this V, attempt to derive r,s,v

		for (;;) { // doesn't actually loop, code will either break or return

			k = ec_buf_to_bignum(V, 32);

			// 0 < k < q256 ?

			if (ec_equal(k, 0) || ec_cmp(k, q256) >= 0) {
				ec_free(k);
				break;
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
				break;
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
				break;
			}

			// success

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

			return;
		}

		// K = HMAC_K(V || 0x00)

		hmac_sha256(K, 32, V, 33, K);
	}
}
