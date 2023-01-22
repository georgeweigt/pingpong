// returns 0 ok, -1 err

int
send_frame(struct node *p, struct atom *msgid, struct atom *msgdata)
{
	int err, len, n, overhead;
	int framelen, msgidlen, msgdatalen, msglen;
	uint8_t *framebuf, *msgbuf;

	msgidlen = rlength(msgid);
	msgdatalen = rlength(msgdata);

	// compensate for possible compression expansion

	if (msgdatalen < 10000)
		overhead = 100; // min
	else
		overhead = msgdatalen / 100; // 1%

	// get frame buffer

	framelen = msgidlen + msgdatalen + overhead + 63; // 63 == hdr (32) + pad (15) + mac (16)

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

	len = compress(framebuf + 32 + msgidlen, msgdatalen + overhead, msgbuf, msgdatalen);

	free(msgbuf);

	if (len == 0) {
		trace();
		free(framebuf);
		return -1;
	}

	msglen = msgidlen + len; // len is compressed length

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

	framelen = 16 * n + 48; // 48 == header (32) + mac (16)

	// encap

	encap_frame(p, framebuf, framelen);

	// send

	err = send_bytes(p->fd, framebuf, framelen);

	free(framebuf);

	return err;
}

// returns 0 ok, -1 err

int
send_frame_uncompressed(struct node *p, struct atom *msgid, struct atom *msgdata)
{
	int err, n;
	int framelen, msgidlen, msgdatalen, msglen;
	uint8_t *framebuf;

	msgidlen = rlength(msgid);
	msgdatalen = rlength(msgdata);

	msglen = msgidlen + msgdatalen;

	n = (msglen + 15) / 16; // number of blocks

	framelen = 16 * n + 48; // header (32) + mac (16)

	framebuf = malloc(framelen);

	if (framebuf == NULL) {
		trace();
		return -1;
	}

	// frame header

	memset(framebuf, 0, 16);

	framebuf[0] = msglen >> 24;
	framebuf[1] = msglen >> 16;
	framebuf[2] = msglen;

	framebuf[3] = 0xc2; // ["",""]
	framebuf[4] = 0x80;
	framebuf[5] = 0x80;

	// frame data

	rencode(framebuf + 32, msgidlen, msgid);
	rencode(framebuf + 32 + msgidlen, msgdatalen, msgdata);

	// erase remaining bytes in last block

	memset(framebuf + 32 + msglen, 0, 16 * n - msglen);

	// encap

	encap_frame(p, framebuf, framelen);

	// send

	err = send_bytes(p->fd, framebuf, framelen);

	free(framebuf);

	return err;
}

void
encap_frame(struct node *p, uint8_t *framebuf, int framelen)
{
	int i;
	uint8_t mac[32], seed[32];

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
}
