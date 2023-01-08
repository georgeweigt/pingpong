void
send_auth(struct node *p)
{
	int len, msglen, n;
	uint8_t *buf, *msg;
	struct atom *list;

	list = auth_body(p);
	msglen = enlength(list);
	msg = malloc(msglen);
	if (msg == NULL)
		exit(1);
	encode(msg, msglen, list);
	free_list(list);

	buf = ecies_encrypt(p, msg, msglen, 2, &len); // header length = 2

	// set length in big endian

	buf[0] = (len - 2) >> 8;
	buf[1] = len - 2;

	// send

	n = send(p->fd, buf, len, 0);

	if (n < 0)
		perror("send");

	printf("%d bytes sent\n", n);

	free(msg);
	free(buf);
}

struct atom *
auth_body(struct node *p)
{
	int i;
	uint8_t buf[32], sig[65];

	// sig (see rlpx.go line 557)

	for (i = 0; i < 32; i++)
		buf[i] = p->shared_secret[i] ^ p->nonce[i];
	signbuf(sig, buf, p->ephemeral_private_key, p->ephemeral_public_key);
	push_string(sig, 65);

	// initiator public key

	push_string(p->public_key, 64);

	// initiator nonce

	push_string(p->nonce, 32);

	// auth version

	push_number(4);

	list(4);

	return pop();
}
