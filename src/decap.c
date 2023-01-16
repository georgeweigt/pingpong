// encap format
//
// prefix || 0x04 || R || iv || c || d
//
// prefix	length (2 bytes)
// R		ephemeral public key (64 bytes)
// iv		initialization vector (16 bytes)
// c		ciphertext
// d		hmac (32 bytes)

int
decap(uint8_t *buf, int len, uint8_t *private_key)
{
	int err, msglen;
	uint8_t *msg;
	uint8_t shared_secret[32];
	uint8_t hmac[32], hmac_key[32];
	uint8_t aes_key[16];
	uint32_t aes_expanded_key[48];

	msg = buf + ENCAP_C;		// ENCAP_C == 2 + 65 + 16
	msglen = len - ENCAP_OVERHEAD;	// ENCAP_OVERHEAD == 2 + 65 + 16 + 32

	// check length

	if (msglen < 0 || (buf[0] << 8 | buf[1]) != len - 2)
		return -1;

	// derive shared_secret from private_key and R

	ec_ecdh(shared_secret, private_key, buf + ENCAP_R + 1); // R + 1 to skip over format byte

	// derive aes_key and hmac_key from ephemeral_shared_secret

	kdf(aes_key, hmac_key, shared_secret);

	// check hmac

	memcpy(hmac, buf + len - 32, 32); // save hmac

	buf[len - 32] = buf[0]; // copy prefix
	buf[len - 31] = buf[1];

	hmac_sha256(hmac_key, 32, buf + ENCAP_IV, msglen + 16 + 2, buf + len - 32); // overwrite received hmac

	err = memcmp(hmac, buf + len - 32, 32); // compare

	if (err)
		return -1; // hmac err

	// decrypt

	aes128ctr_setup(aes_expanded_key, aes_key, buf + ENCAP_IV);
	aes128ctr_encrypt(aes_expanded_key, msg, msglen); // encrypt does decrypt in CTR mode

	return 0;
}
