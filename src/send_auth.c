int
send_auth(struct node *p)
{
	int err, len, msglen, n;
	uint8_t *buf;
	struct atom *q;

	q = auth_body(p);

	msglen = rlength(q);

	n = 100 + randf() % 100; // random pad length, at least 100

	len = msglen + n + ENCAP_OVERHEAD; // ENCAP_OVERHEAD == 2 + 65 + 16 + 32

	buf = alloc_mem(len);

	if (buf == NULL)
		exit(1);

	memset(buf, 0, len);

	rencode(buf + ENCAP_C, msglen, q); // ENCAP_C == 2 + 65 + 16

	free_list(q);

	encap(buf, len, p->far_public_key);

	save_auth_for_session_setup(p, buf, len);

	err = send_bytes(p->fd, buf, len);

	free_mem(buf);

	return err;
}

struct atom *
auth_body(struct node *p)
{
	int i;
	uint8_t hash[32], sig[65];

	// sig (see rlpx.go line 557)

	for (i = 0; i < 32; i++)
		hash[i] = p->static_shared_secret[i] ^ p->auth_nonce[i];

	// auth_public_key is recovered from sig

	ec_sign(sig, hash, p->auth_private_key);

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
