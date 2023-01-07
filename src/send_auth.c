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
	uint8_t sig[32];

	// sig

	keccak256(sig, p->ephemeral_public_key, 64);
	push_string(sig, 32);

	// initiator public key

	push_string(p->public_key, 64);

	// initiator nonce

	push_string(p->nonce, 32);

	// auth version

	push_number(4);

	list(4);

	return pop();
}
