int
send_frame(struct node *p, struct atom *msgid, struct atom *msgdata)
{
	int err, i, len, n;
	int msgidlen, msgdatalen;
	int framelen, msglen;
	uint8_t *framebuf, *msgbuf;
	uint8_t mac[32], seed[32];

	msgidlen = rlength(msgid);
	msgdatalen = rlength(msgdata);

	// get frame buffer

	framelen = msgidlen + msgdatalen + 74; // hdr (32) + pad (16) + mac (16) + expansion (10)

	framebuf = malloc(framelen);

	if (framebuf == NULL) {
		trace();
		return -1;
	}

	// encode msg data

	msgbuf = malloc(msgdatalen);

	if (msgbuf == NULL) {
		trace();
		free(framebuf);
		return -1;
	}

	rencode(msgbuf, msgdatalen, msgdata);

	// compress

	len = compress(framebuf + 32 + msgidlen, msgdatalen + 10, msgbuf, msgdatalen);

	free(msgbuf);

	if (len == 0) {
		trace();
		free(framebuf);
		return -1;
	}

	msglen = msgidlen + len;

	// header

	memset(framebuf, 0, 16);

	framebuf[0] = msglen >> 24;
	framebuf[1] = msglen >> 16;
	framebuf[2] = msglen;

	framebuf[3] = 0xc2; // ["",""]
	framebuf[4] = 0x80;
	framebuf[5] = 0x80;

	// msg id

	rencode(framebuf + 32, msgidlen, msgid);

	// erase remaining bytes in last block

	n = (msglen + 15) / 16; // number of blocks
	memset(framebuf + 32 + msglen, 0, 16 * n - msglen);

	// new frame length

	framelen = 32 + 16 * n + 16;

	// encap frame header

	aes256ctr_encrypt(p->encrypt_state, framebuf, 16);

	// header-mac-seed = aes(mac-secret, keccak256.digest(egress-mac)[:16]) ^ header-ciphertext
	// egress-mac = keccak256.update(egress-mac, header-mac-seed)
	// header-mac = keccak256.digest(egress-mac)[:16]

	keccak256_digest(&p->egress_mac, mac);

	aes256_encrypt_block(p->egress_mac.expanded_key, mac, seed);

	for (i = 0; i < 16; i++)
		seed[i] ^= framebuf[i];

	keccak256_update(&p->egress_mac, seed, 16);

	keccak256_digest(&p->egress_mac, mac);

	memcpy(framebuf + 16, mac, 16);

	// encap frame data

	aes256ctr_encrypt(p->encrypt_state, framebuf + 32, framelen - 48);

	// egress-mac = keccak256.update(egress-mac, frame-ciphertext)
	// frame-mac-seed = aes(mac-secret, keccak256.digest(egress-mac)[:16]) ^ keccak256.digest(egress-mac)[:16]
	// egress-mac = keccak256.update(egress-mac, frame-mac-seed)
	// frame-mac = keccak256.digest(egress-mac)[:16]

	keccak256_update(&p->egress_mac, framebuf + 32, framelen - 48);

	keccak256_digest(&p->egress_mac, mac);

	aes256_encrypt_block(p->egress_mac.expanded_key, mac, seed);

	for (i = 0; i < 16; i++)
		seed[i] ^= mac[i];

	keccak256_update(&p->egress_mac, seed, 16);

	keccak256_digest(&p->egress_mac, mac);

	memcpy(framebuf + framelen - 16, mac, 16);

	err = send_bytes(p->fd, framebuf, framelen);

	free(framebuf);

	return err;
}

int
send_frame_unc(struct node *p, struct atom *msg_id, struct atom *msg_data)
{
	int err, i, n;
	int msg_id_len, msg_data_len, msglen;
	uint8_t *buf, mac[32], seed[32];

	msg_id_len = rlength(msg_id);
	msg_data_len = rlength(msg_data);

	msglen = msg_id_len + msg_data_len;

	n = (msglen + 15) / 16 + 3; // number of blocks

	buf = malloc(16 * n);

	if (buf == NULL)
		exit(1);

	memset(buf, 0, 16 * n);

	buf[0] = msglen >> 24;
	buf[1] = msglen >> 16;
	buf[2] = msglen;

	buf[3] = 0xc2; // ["",""]
	buf[4] = 0x80;
	buf[5] = 0x80;

	aes256ctr_encrypt(p->encrypt_state, buf, 16);

	// header-mac-seed = aes(mac-secret, keccak256.digest(egress-mac)[:16]) ^ header-ciphertext
	// egress-mac = keccak256.update(egress-mac, header-mac-seed)
	// header-mac = keccak256.digest(egress-mac)[:16]

	keccak256_digest(&p->egress_mac, mac);

	aes256_encrypt_block(p->egress_mac.expanded_key, mac, seed);

	for (i = 0; i < 16; i++)
		seed[i] ^= buf[i];

	keccak256_update(&p->egress_mac, seed, 16);

	keccak256_digest(&p->egress_mac, mac);

	memcpy(buf + 16, mac, 16);

	// data

	rencode(buf + 32, msg_id_len, msg_id);
	rencode(buf + 32 + msg_id_len, msg_data_len, msg_data);

	aes256ctr_encrypt(p->encrypt_state, buf + 32, 16 * n - 48);

	// egress-mac = keccak256.update(egress-mac, frame-ciphertext)
	// frame-mac-seed = aes(mac-secret, keccak256.digest(egress-mac)[:16]) ^ keccak256.digest(egress-mac)[:16]
	// egress-mac = keccak256.update(egress-mac, frame-mac-seed)
	// frame-mac = keccak256.digest(egress-mac)[:16]

	keccak256_update(&p->egress_mac, buf + 32, 16 * n - 48);

	keccak256_digest(&p->egress_mac, mac);

	aes256_encrypt_block(p->egress_mac.expanded_key, mac, seed);

	for (i = 0; i < 16; i++)
		seed[i] ^= mac[i];

	keccak256_update(&p->egress_mac, seed, 16);

	keccak256_digest(&p->egress_mac, mac);

	memcpy(buf + 16 * n - 16, mac, 16);

	err = send_bytes(p->fd, buf, 16 * n);

	free(buf);

	return err;
}
