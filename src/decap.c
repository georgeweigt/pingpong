// prefix	2 bytes
// public key	65 bytes
// iv		16 bytes
// ciphertext	msglen bytes
// hmac		32 bytes

#define R 2
#define IV (2 + 65)
#define C (2 + 65 + 16)
#define OVERHEAD (2 + 65 + 16 + 32)

// returns 0 ok, -1 err

int
decap(uint8_t *buf, int len, uint8_t *private_key)
{
	int err, msglen;
	uint8_t shared_secret[32];
	uint8_t hmac[32], hmac_key[32];
	uint8_t aes_key[16];
	uint32_t aes_expanded_key[64];

	msglen = len - OVERHEAD;

	// check length

	if (msglen < 0 || (buf[0] << 8 | buf[1]) != len - 2)
		return -1;

	// derive shared_secret from private_key and R

	ec_ecdh(shared_secret, private_key, buf + R + 1); // R + 1 to skip over format byte

	// derive aes_key and hmac_key from ephemeral_shared_secret

	kdf(aes_key, hmac_key, shared_secret);

	// check hmac

	memcpy(hmac, buf + len - 32, 32); // save hmac

	buf[len - 32] = buf[0]; // copy prefix
	buf[len - 31] = buf[1];

	hmac_sha256(hmac_key, 32, buf + IV, msglen + 16 + 2, buf + len - 32); // overwrite received hmac

	err = memcmp(hmac, buf + len - 32, 32); // compare

	if (err)
		return -1; // hmac err

	// decrypt

	aes128ctr_expandkey(aes_expanded_key, aes_key, buf + IV);
	aes128ctr_encrypt(aes_expanded_key, buf + C, msglen); // encrypt does decrypt in CTR mode

	return 0;
}

#undef R
#undef IV
#undef C
#undef OVERHEAD
