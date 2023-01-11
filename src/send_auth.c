#define C (2 + 65 + 16) // prefix + R + iv
#define OVERHEAD (2 + 65 + 16 + 32) // prefix + R + iv + hmac

void
send_auth(struct node *p)
{
	int len, msglen, n;
	uint8_t *buf;
	struct atom *list;

	list = auth_body(p);
	msglen = enlength(list);

	// pad with random amount of data, at least 100 bytes

	n = 100 + random() % 100;

	len = msglen + n + OVERHEAD;

	buf = malloc(len);

	if (buf == NULL)
		exit(1);

	rencode(buf + C, msglen, list);

	free_list(list);

	encap(buf, len, p);

	// send

	n = send(p->fd, buf, len, 0);

	free(buf);

	if (n < 0)
		perror("send");

	printf("%d bytes sent\n", n);
}

struct atom *
auth_body(struct node *p)
{
	int i;
	uint8_t hash[32], sig[65];

	// sig (see rlpx.go line 557)

	for (i = 0; i < 32; i++)
		hash[i] = p->static_shared_secret[i] ^ p->nonce[i];

	ec_sign(sig, sig + 32, hash, p->private_key);

	sig[64] = p->public_key[63] & 1;

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

#undef C
#undef OVERHEAD
