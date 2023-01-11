// prefix	2 bytes
// public key	65 bytes
// iv		16 bytes
// ciphertext	msglen bytes
// hmac		32 bytes

#define R 2
#define IV (2 + 65)
#define C (2 + 65 + 16)
#define OVERHEAD (2 + 65 + 16 + 32)

int
receive_auth(struct node *p, uint8_t *buf, int len)
{
	int err, msglen;
	struct atom *list;

	err = decap(buf, len, p->private_key);

	if (err)
		return -1;

	msglen = len - OVERHEAD;

	err = rdecode_relax(buf + C, msglen);

	if (err)
		return -1;

	list = pop();

	// FIXME validate list

	// save peer public key

	memcpy(p->peer_public_key, list->cdr->car->string, 64);

	free_list(list);

	return 0;
}

#undef R
#undef IV
#undef C
#undef OVERHEAD
