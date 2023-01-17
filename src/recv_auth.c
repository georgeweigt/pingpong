int
recv_auth(struct node *p)
{
	int err, msglen, len, n;
	uint8_t *buf, *msg;
	struct atom *q;

	buf = recv_msg(p->fd);

	if (buf == NULL)
		return -1;

	len = (buf[0] << 8 | buf[1]) + 2; // length from prefix

	save_auth_for_session_setup(p, buf, len);

	err = decap(buf, len, p->private_key);

	if (err) {
		free(buf);
		return -1;
	}

	msg = buf + ENCAP_C;		// ENCAP_C == 2 + 65 + 16
	msglen = len - ENCAP_OVERHEAD;	// ENCAP_OVERHEAD == 2 + 65 + 16 + 32

	n = rdecode_relax(msg, msglen);

	free(buf);

	if (n < 0) {
		trace();
		return -1;
	}

	q = pop(); // result of rdecode

	err = recv_auth_data(p, q);

	free_list(q);

	return err;
}

int
recv_auth_data(struct node *p, struct atom *q)
{
	struct atom *q1, *q2, *q3;

	// length == -1 indicates a list item

	if (q == NULL || q->length != -1 || q->cdr == NULL || q->cdr->cdr == NULL) {
		trace();
		return -1;
	}

	q1 = q->car;		// 1st item: sig
	q2 = q->cdr->car;	// 2nd item: public key
	q3 = q->cdr->cdr->car;	// 3rd item: nonce

	if (q1 == NULL || q2 == NULL || q3 == NULL) {
		trace();
		return -1;
	}

	if (q2->length != 64 || q3->length != 32) {
		trace();
		return -1;
	}

	memcpy(p->auth_nonce, q3->string, 32);

	return 0;
}
