// prefix	2 bytes
// public key	65 bytes
// iv		16 bytes
// ciphertext	msglen bytes
// hmac		32 bytes

int
recv_auth(struct node *p, uint8_t *buf, int len)
{
	int err, msglen;
	struct atom *q;

	err = decap(buf, len, p->private_key);

	if (err)
		return -1;

	memcpy(p->auth_public_key, buf + 3, 64);

	msglen = len - ENCAP_OVERHEAD; // ENCAP_OVERHEAD == 2 + 65 + 16 + 32

	err = rdecode_relax(buf + ENCAP_C, msglen);

	if (err)
		return -1;

	q = pop();

	err = recv_auth_data(p, q);

	free_list(q);

	return err;
}

int
recv_auth_data(struct node *p, struct atom *q)
{
	struct atom *q1, *q2, *q3;

	// length == -1 indicates a list item

	if (q == NULL || q->length != -1 || q->cdr == NULL || q->cdr->cdr == NULL)
		return -1;

	q1 = q->car;		// 1st item: sig
	q2 = q->cdr->car;	// 2nd item: public key
	q3 = q->cdr->cdr->car;	// 3rd item: nonce

	if (q1 == NULL || q2 == NULL || q3 == NULL)
		return -1;

	if (q2->length != 64 || q3->length != 32)
		return -1;

	memcpy(p->auth_nonce, q3->string, 32);

	return 0;
}
