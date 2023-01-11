#define C (2 + 65 + 16)
#define OVERHEAD (2 + 65 + 16 + 32)

int
recv_ack(struct node *p, uint8_t *buf, int len)
{
	int err, msglen;
	uint8_t *msg;
	struct atom *list, *t;

	err = decap(buf, len, p->private_key);

	if (err)
		return -1;

	msg = buf + C;
	msglen = len - OVERHEAD;

	err = rdecode_relax(msg, msglen); // relax allows trailing data

	if (err)
		return -1;

	list = pop();

	t = list;

	if (t == NULL || t->car == NULL || t->car->length < 0) {
		free_list(list);
		return -1;
	}

	printf("recipient ephemeral public key\n");

	printmem(t->car->string, t->car->length);

	t = t->cdr;

	if (t == NULL || t->car == NULL || t->car->length < 0) {
		free_list(list);
		return -1;
	}

	printf("recipient nonce\n");

	printmem(t->car->string, t->car->length);

	t = t->cdr;

	if (t == NULL || t->car == NULL || t->car->length < 0) {
		free_list(list);
		return -1;
	}

	printf("version\n");

	printmem(t->car->string, t->car->length);

	free_list(list);

	return 0;
}

#undef C
#undef OVERHEAD
