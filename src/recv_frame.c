uint8_t *
recv_frame(struct node *p)
{
	int err, i, len, n;
	uint8_t *buf, header[32], mac[32], seed[32];

	err = recv_bytes(p->fd, header, 32);

	if (err)
		return NULL;

	// header-mac-seed = aes(mac-secret, keccak256.digest(ingress-mac)[:16]) ^ header-ciphertext
	// ingress-mac = keccak256.update(ingress-mac, header-mac-seed)
	// header-mac = keccak256.digest(ingress-mac)[:16]

	keccak256_digest(&p->ingress_mac, mac);

	aes256_encrypt_block(p->ingress_mac.enc_state, mac, seed);

	for (i = 0; i < 16; i++)
		seed[i] ^= header[i];

	keccak256_update(&p->ingress_mac, seed, 16);

	keccak256_digest(&p->ingress_mac, mac);

	// check header mac

	err = memcmp(mac, header + 16, 16);

	if (err) {
		trace();
		NULL;
	}

	// decrypt header

	aes256ctr_encrypt(p->decrypt_state, header, 16);

	// length from prefix

	len = header[0] << 16 | header[1] << 8 | header[2];

	n = (len + 15) / 16; // number of blocks

	buf = malloc(16 * n + 48); // additional blocks for header and mac

	if (buf == NULL)
		exit(1);

	memcpy(buf, header, 32);

	recv_bytes(p->fd, buf + 32, 16 * n + 16);

	// ingress-mac = keccak256.update(ingress-mac, frame-ciphertext)
	// frame-mac-seed = aes(mac-secret, keccak256.digest(ingress-mac)[:16]) ^ keccak256.digest(ingress-mac)[:16]
	// ingress-mac = keccak256.update(ingress-mac, frame-mac-seed)
	// frame-mac = keccak256.digest(ingress-mac)[:16]

	keccak256_update(&p->ingress_mac, buf + 32, 16 * n);

	keccak256_digest(&p->ingress_mac, mac);

	aes256_encrypt_block(p->ingress_mac.enc_state, mac, seed);

	for (i = 0; i < 16; i++)
		seed[i] ^= mac[i];

	keccak256_update(&p->ingress_mac, seed, 16);

	keccak256_digest(&p->ingress_mac, mac);

	// check frame mac

	err = memcmp(mac, buf + 32 + 16 * n, 16);

	if (err) {
		trace();
		free(buf);
		return NULL;
	}

	// decrypt

	aes256ctr_encrypt(p->decrypt_state, buf + 32, 16 * n);

	return buf;
}
