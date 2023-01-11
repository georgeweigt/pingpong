// encap format
//
// prefix || 0x04 || R || iv || c || d
//
// prefix	length (2 bytes)
// R		ephemeral public key (64 bytes)
// iv		initialization vector (16 bytes)
// c		ciphertext
// d		hmac (32 bytes)

void
encap(uint8_t *buf, int len, uint8_t *peer_public_key)
{
	int i, msglen;
	uint8_t *msg;
	uint8_t e_private_key[32], e_public_key[64]; // ephemeral keys
	uint8_t shared_secret[32];
	uint8_t hmac_key[32];
	uint8_t aes_key[16];
	uint32_t aes_expanded_key[64];

	msg = buf + ENCAP_C;		// ENCAP_C == 2 + 65 + 16
	msglen = len - ENCAP_OVERHEAD;	// ENCAP_OVERHEAD == 2 + 65 + 16 + 32

	// generate e_private_key and e_public_key

	ec_genkey(e_private_key, e_public_key);

	// derive shared_secret from private_key and peer_public_key

	ec_ecdh(shared_secret, e_private_key, peer_public_key);

	// derive AES and HMAC keys from shared_secret

	kdf(aes_key, hmac_key, shared_secret);

	// prefix

	buf[0] = (len - 2) >> 8;
	buf[1] = len - 2;

	// ephemeral key R

	buf[ENCAP_R] = 0x04; // uncompressed format
	memcpy(buf + ENCAP_R + 1, e_public_key, 64);

	// iv

	for (i = 0; i < 16; i++)
		buf[ENCAP_IV + i] = random();

	// encrypt the message

	aes128ctr_expandkey(aes_expanded_key, aes_key, buf + ENCAP_IV);
	aes128ctr_encrypt(aes_expanded_key, msg, msglen);

	// compute hmac over IV || C || prefix

	buf[len - 32] = buf[0];
	buf[len - 31] = buf[1];

	hmac_sha256(hmac_key, 32, buf + ENCAP_IV, msglen + 16 + 2, buf + len - 32);
}
