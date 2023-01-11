void
secrets(struct node *p, uint8_t *ack_public_key, uint8_t *ack_nonce)
{
	uint8_t ephemeral_key[32];
	uint8_t shared_secret[32];
	uint8_t buf[64];

	// ephemeral_key = auth_private_key * ack_public_key

	ec_ecdh(ephemeral_key, p->auth_private_key, ack_public_key);

	// derive shared secret

	memcpy(buf, ack_nonce, 32);
	memcpy(buf + 32, p->nonce, 32);

	keccak256(buf + 32, buf, 64);

	memcpy(buf, ephemeral_key, 32);

	keccak256(shared_secret, buf, 64);

	// derive AES secret

	memcpy(buf, ephemeral_key, 32);
	memcpy(buf + 32, shared_secret, 32);

	keccak256(p->aes_secret, buf, 64);

	// derive HMAC secret

	memcpy(buf, ephemeral_key, 32);
	memcpy(buf + 32, p->aes_secret, 32);

	keccak256(p->hmac_secret, buf, 64);
}
