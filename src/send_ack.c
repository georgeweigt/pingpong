int
send_ack(struct node *p)
{
	int err, len, msglen, n;
	uint8_t *buf;
	struct atom *q;

	q = ack_body(p);

	msglen = rlength(q);

	n = 100 + random() % 100; // random pad length, at least 100

	len = msglen + n + ENCAP_OVERHEAD; // ENCAP_OVERHEAD == 2 + 65 + 16 + 32

	buf = malloc(len);

	if (buf == NULL)
		exit(1);

	memset(buf, 0, len);

	rencode(buf + ENCAP_C, msglen, q); // ENCAP_C == 2 + 65 + 16

	free_list(q);

	encap(buf, len, p->far_public_key);

	save_ack_for_session_setup(p, buf, len);

	err = send_bytes(p->fd, buf, len);

	free(buf);

	return err;
}

struct atom *
ack_body(struct node *p)
{
	// public key

	push_string(p->ack_public_key, 64);

	// nonce

	push_string(p->ack_nonce, 32);

	// version

	push_number(4);

	list(3);

	return pop();
}
