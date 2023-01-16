int
recv_ack(struct node *p)
{
	int err, msglen, len;
	uint8_t *buf, *msg;
	struct atom *q;

	buf = recv_msg(p->fd);

	if (buf == NULL)
		return -1;

	len = (buf[0] << 8 | buf[1]) + 2; // length from prefix

	save_ack_for_session_setup(p, buf, len);

	err = decap(buf, len, p->private_key);

	if (err) {
		free(buf);
		return -1;
	}

	msg = buf + ENCAP_C;		// ENCAP_C == 2 + 65 + 16
	msglen = len - ENCAP_OVERHEAD;	// ENCAP_OVERHEAD == 2 + 65 + 16 + 32

	err = rdecode_relax(msg, msglen); // relax allows trailing data

	free(buf);

	if (err) {
		trace();
		return -1;
	}

	q = pop(); // result from rdecode

	err = recv_ack_data(p, q);

	free_list(q);

	return err;
}

int
recv_ack_data(struct node *p, struct atom *q)
{
	struct atom *q1, *q2;

	// length == -1 indicates a list item

	if (q == NULL || q->length != -1 || q->cdr == NULL) {
		trace();
		return -1;
	}

	q1 = q->car;		// 1st item: ephemeral public key
	q2 = q->cdr->car;	// 2nd item: nonce

	if (q1 == NULL || q2 == NULL) {
		trace();
		return -1;
	}

	if (q1->length != 64 || q2->length != 32) {
		trace();
		return -1;
	}

	memcpy(p->ack_public_key, q1->string, 64);
	memcpy(p->ack_nonce, q2->string, 32);

	return 0;
}
