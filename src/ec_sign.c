// rbuf		32 bytes (result)
// sbuf		32 bytes (result)
// hash		32 bytes
// private_key	32 bytes

void
ec_sign(uint8_t *rbuf, uint8_t *sbuf, uint8_t *hash, uint8_t *private_key)
{
	int err, i;
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

	for (;;) {

		// V = HMAC_K(V)

		hmac_sha256(K, 32, V, 32, V);

		// for this V, attempt to derive r and s

		for (;;) {

			k = ec_buf_to_bignum(V, 32);

			// 0 < k < q256 ?

			if (ec_equal(k, 0) || ec_cmp(k, q256) >= 0) {
				ec_free(k);
				break;
			}

			// R = k * G

			ec_mult(&R, k, &G, p256);
			err = ec_affinify(&R, p256);

			if (err) {
				ec_free(k);
				ec_free_xyz(&R);
				break;
			}

			// r = R.x mod n

			r = ec_dup(R.x);
			ec_mod(r, q256);

			if (ec_equal(r, 0)) {
				ec_free(k);
				ec_free(r);
				ec_free_xyz(&R);
				break;
			}

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

			if (ec_equal(s, 0)) {
				ec_free(k);
				ec_free(r);
				ec_free(s);
				ec_free_xyz(&R);
				break;
			}

			// success

			// save r

			memset(rbuf, 0, 32);

			for (i = 0; i < len(r); i++) {
				if (32 - 4 * i - 4 < 0)
					break; // err, result greater than 32 bytes, truncate
				// bignums are LE, this converts to BE
				rbuf[32 - 4 * i - 4] = r[i] >> 24;
				rbuf[32 - 4 * i - 3] = r[i] >> 16;
				rbuf[32 - 4 * i - 2] = r[i] >> 8;
				rbuf[32 - 4 * i - 1] = r[i];
			}

			// save s

			memset(sbuf, 0, 32);

			for (i = 0; i < len(s); i++) {
				if (32 - 4 * i - 4 < 0)
					break; // err, result greater than 32 bytes, truncate
				// bignums are LE, this converts to BE
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
			ec_free(G.z);
			ec_free_xyz(&R);

			return;
		}

		// K = HMAC_K(V || 0x00)

		hmac_sha256(K, 32, V, 33, K);
	}
}
