// returns 0 ok, -1 err

// if ok, returns msg id and msg data on stack

int
recv_frame_uncompressed(struct node *p)
{
	int err, i, len, nblocks, nbytes;
	uint8_t *buf, header[32], mac[32], seed[32];

	err = recv_bytes(p->fd, header, 32);

	if (err) {
		trace();
		return -1;
	}

	// header-mac-seed = aes(mac-secret, keccak256.digest(ingress-mac)[:16]) ^ header-ciphertext
	// ingress-mac = keccak256.update(ingress-mac, header-mac-seed)
	// header-mac = keccak256.digest(ingress-mac)[:16]

	keccak256_digest(&p->ingress_mac, mac);

	aes256_encrypt_block(p->ingress_mac.expanded_key, mac, seed);

	for (i = 0; i < 16; i++)
		seed[i] ^= header[i];

	keccak256_update(&p->ingress_mac, seed, 16);

	keccak256_digest(&p->ingress_mac, mac);

	// check header mac

	err = memcmp(mac, header + 16, 16);

	if (err) {
		trace();
		return -1;
	}

	// decrypt header

	aes256ctr_encrypt(p->decrypt_state, header, 16);

	// length from prefix

	len = header[0] << 16 | header[1] << 8 | header[2];

	nblocks = (len + 15) / 16; // number of blocks

	buf = malloc(16 * nblocks + 16); // one additional block for mac

	if (buf == NULL) {
		trace();
		return -1;
	}

	recv_bytes(p->fd, buf, 16 * nblocks + 16);

	// ingress-mac = keccak256.update(ingress-mac, frame-ciphertext)
	// frame-mac-seed = aes(mac-secret, keccak256.digest(ingress-mac)[:16]) ^ keccak256.digest(ingress-mac)[:16]
	// ingress-mac = keccak256.update(ingress-mac, frame-mac-seed)
	// frame-mac = keccak256.digest(ingress-mac)[:16]

	keccak256_update(&p->ingress_mac, buf, 16 * nblocks);

	keccak256_digest(&p->ingress_mac, mac);

	aes256_encrypt_block(p->ingress_mac.expanded_key, mac, seed);

	for (i = 0; i < 16; i++)
		seed[i] ^= mac[i];

	keccak256_update(&p->ingress_mac, seed, 16);

	keccak256_digest(&p->ingress_mac, mac);

	// check frame mac

	err = memcmp(mac, buf + 16 * nblocks, 16);

	if (err) {
		trace();
		free(buf);
		return -1;
	}

	// decrypt

	aes256ctr_encrypt(p->decrypt_state, buf, 16 * nblocks);

	// decode

	// msg id

	nbytes = rdecode_relax(buf, len);

	if (nbytes < 0) {
		trace();
		free(buf);
		return -1;
	}

	// msg data

	nbytes = rdecode_relax(buf + nbytes, len - nbytes);

	if (nbytes < 0) {
		trace();
		free(buf);
		free_list(pop());
		return -1;
	}

	free(buf);

	return 0;
}
