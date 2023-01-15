void
secrets(struct node *p)
{
	uint8_t ephemeral_secret[32];
	uint8_t shared_secret[32];
	uint8_t buf[64];

	// ephemeral_secret = auth_private_key * ack_public_key

	ec_ecdh(ephemeral_secret, p->auth_private_key, p->ack_public_key);

	// shared_secret = keccak256(ephemeral_secret || keccak256(ack_nonce || auth_nonce))

	memcpy(buf, p->ack_nonce, 32);
	memcpy(buf + 32, p->auth_nonce, 32);

	keccak256(buf + 32, buf, 64);

	memcpy(buf, ephemeral_secret, 32);

	keccak256(shared_secret, buf, 64);

	// aes_secret = keccak256(ephemeral_secret || shared_secret)

	memcpy(buf, ephemeral_secret, 32);
	memcpy(buf + 32, shared_secret, 32);

	keccak256(p->aes_secret, buf, 64);

	// mac_secret = keccak256(ephemeral_secret || aes_secret)

	memcpy(buf, ephemeral_secret, 32);
	memcpy(buf + 32, p->aes_secret, 32);

	keccak256(p->mac_secret, buf, 64);
}
