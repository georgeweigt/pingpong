// this is done after completion of AUTH/ACK exchange

void
session_setup(struct node *p, int initiator)
{
	int i;
	uint8_t ephemeral_secret[32];
	uint8_t shared_secret[32];
	uint8_t buf[64], iv[16];
	struct mac_state_t *u, *v;

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

	// setup aes

	memset(iv, 0, 16);

	aes256ctr_setup(p->encrypt_state, p->aes_secret, iv);
	aes256ctr_setup(p->decrypt_state, p->aes_secret, iv);

	aes256ctr_setup(p->ingress_mac.expanded_key, p->mac_secret, iv);
	aes256ctr_setup(p->egress_mac.expanded_key, p->mac_secret, iv);

	// macs

	keccak256_setup(&p->ingress_mac);
	keccak256_setup(&p->egress_mac);

	if (initiator) {
		u = &p->ingress_mac;
		v = &p->egress_mac;
	} else {
		v = &p->ingress_mac; // interchange for recipient
		u = &p->egress_mac;
	}

	// ingress-mac = keccak256.init((mac-secret ^ initiator-nonce) || ack)

	for (i = 0; i < 32; i++)
		buf[i] = p->mac_secret[i] ^ p->auth_nonce[i];

	keccak256_update(u, buf, 32);
	keccak256_update(u, p->ack_buf, p->ack_len);

	// egress-mac = keccak256.init((mac-secret ^ recipient-nonce) || auth)

	for (i = 0; i < 32; i++)
		buf[i] = p->mac_secret[i] ^ p->ack_nonce[i];

	keccak256_update(v, buf, 32);
	keccak256_update(v, p->auth_buf, p->auth_len);
}

void
save_auth_for_session_setup(struct node *p, uint8_t *auth, int len)
{
	uint8_t *buf;

	buf = malloc(len);

	if (buf == NULL)
		exit(1);

	memcpy(buf, auth, len);

	if (p->auth_buf)
		free(p->auth_buf);

	p->auth_buf = buf;
	p->auth_len = len;
}

void
save_ack_for_session_setup(struct node *p, uint8_t *ack, int len)
{
	uint8_t *buf;

	buf = malloc(len);

	if (buf == NULL)
		exit(1);

	memcpy(buf, ack, len);

	if (p->ack_buf)
		free(p->ack_buf);

	p->ack_buf = buf;
	p->ack_len = len;
}
