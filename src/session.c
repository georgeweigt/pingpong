void
session(struct node *p, int initiator)
{
	int i;
	uint8_t ephemeral_secret[32];
	uint8_t shared_secret[32];
	uint8_t buf[64], iv[16];
	struct mac *a, *b;

	// ephemeral_secret = ephemeral private_key * ephemeral public_key

	if (initiator)
		ec_ecdh(ephemeral_secret, p->auth_private_key, p->ack_public_key);
	else
		ec_ecdh(ephemeral_secret, p->ack_private_key, p->auth_public_key);

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

	// setup enc/dec streams

	memset(iv, 0, 16);

	aes256ctr_setup(p->encrypt_state, p->aes_secret, iv);
	aes256ctr_setup(p->decrypt_state, p->aes_secret, iv);

	if (initiator) {
		a = &p->ingress_mac;
		b = &p->egress_mac;
	} else {
		a = &p->egress_mac; // interchange for recipient
		b = &p->ingress_mac;
	}

	// initiator ingress-mac = keccak256.init((mac-secret ^ initiator-nonce) || ack)

	for (i = 0; i < 32; i++)
		buf[i] = p->mac_secret[i] ^ p->auth_nonce[i];

	keccak256_init(a);
	keccak256_update(a, buf, 32);
	keccak256_update(a, p->ack_buf, p->ack_len);

	// initiator egress-mac = keccak256.init((mac-secret ^ recipient-nonce) || auth)

	for (i = 0; i < 32; i++)
		buf[i] = p->mac_secret[i] ^ p->ack_nonce[i];

	keccak256_init(b);
	keccak256_update(b, buf, 32);
	keccak256_update(b, p->auth_buf, p->auth_len);
}
