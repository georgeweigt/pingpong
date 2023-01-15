void
send_ack(struct node *p)
{
	int len, msglen, n;
	uint8_t *buf;
	struct atom *q;

	q = ack_body(p);

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

	if (p->ack_buf)
		free(p->ack_buf);

	p->ack_buf = buf;
	p->ack_len = len;

	// send buf

	n = send(p->fd, buf, len, 0);

	if (n < 0)
		perror("send");

	printf("%d bytes sent\n", n);
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
