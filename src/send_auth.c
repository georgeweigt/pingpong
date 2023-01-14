void
send_auth(struct node *p)
{
	int i, len, msglen, n;
	uint8_t *buf;
	struct atom *q;

	for (i = 0; i < 32; i++)
		p->auth_nonce[i] = random();

	q = auth_body(p);

	msglen = enlength(q);

	// pad with random amount of data, at least 100 bytes

	n = 100 + random() % 100;

	len = msglen + n + ENCAP_OVERHEAD; // ENCAP_OVERHEAD == 2 + 65 + 16 + 32

	buf = malloc(len);

	if (buf == NULL)
		exit(1);

	rencode(buf + ENCAP_C, msglen, q); // ENCAP_C == 2 + 65 + 16

	free_list(q);

	encap(buf, len, p);

	// save buf for later

	if (p->auth_buf)
		free(p->auth_buf);

	p->auth_buf = buf;
	p->auth_len = len;

	// send buf

	n = send(p->fd, buf, len, 0);

	if (n < 0)
		perror("send");

	printf("%d bytes sent\n", n);
}

struct atom *
auth_body(struct node *p)
{
	int i;
	uint8_t hash[32], sig[65];

	// sig (see rlpx.go line 557)

	for (i = 0; i < 32; i++)
		hash[i] = p->static_shared_secret[i] ^ p->auth_nonce[i];

	ec_sign(sig, sig + 32, hash, p->private_key);

	sig[64] = p->public_key[63] & 1;

	push_string(sig, 65);

	// initiator public key

	push_string(p->public_key, 64);

	// initiator nonce

	push_string(p->auth_nonce, 32);

	// auth version

	push_number(4);

	list(4);

	return pop();
}
