int
recv_ack(struct node *p, uint8_t *buf, int len)
{
	int err, msglen;
	uint8_t *msg;
	struct atom *q;

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
	uint8_t *ack_public_key;
	uint8_t *ack_nonce;

	// length == -1 indicates a list item

	if (q == NULL || q->length != -1 || q->cdr == NULL)
		return -1;

	q1 = q->car;		// 1st item: recipient ephemeral public key
	q2 = q->cdr->car;	// 2nd item: recipient nonce

	if (q1 == NULL || q2 == NULL)
		return -1;

	if (q1->length != 64 || q2->length != 32)
		return -1;

	ack_public_key = q1->string;
	ack_nonce = q2->string;

	secrets(p, ack_public_key, ack_nonce);

	return 0;
}