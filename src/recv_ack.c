int
recv_ack(struct node *p, uint8_t *buf, int len)
{
	int err, msglen;
	uint8_t *msg;
	struct atom *q;

	// save a copy of buf for later

	if (p->ack_buf)
		free(p->ack_buf);
	p->ack_buf = malloc(len);
	if (p->ack_buf == NULL)
		exit(1);
	memcpy(p->ack_buf, buf, len);
	p->ack_len = len;

	// decrypt

	err = decap(buf, len, p->private_key);

	if (err)
		return -1;

	msg = buf + ENCAP_C;		// ENCAP_C == 2 + 65 + 16
	msglen = len - ENCAP_OVERHEAD;	// ENCAP_OVERHEAD == 2 + 65 + 16 + 32

	err = rdecode_relax(msg, msglen); // relax allows trailing data

	if (err)
		return -1;

	q = pop(); // result from rdecode

	err = recv_ack_data(p, q);

	free_list(q);

	return err;
}

// returns 0 ok, -1 err

int
recv_ack_data(struct node *p, struct atom *q)
{
	struct atom *q1, *q2;

	// length == -1 indicates a list item

	if (q == NULL || q->length != -1 || q->cdr == NULL)
		return -1;

	q1 = q->car;		// 1st item: ephemeral public key
	q2 = q->cdr->car;	// 2nd item: nonce

	if (q1 == NULL || q2 == NULL)
		return -1;

	if (q1->length != 64 || q2->length != 32)
		return -1;

	memcpy(p->ack_public_key, q1->string, 64);
	memcpy(p->ack_nonce, q2->string, 32);

	return 0;
}
