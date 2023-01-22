// returns 0 ok, -1 err

int
recv_hello(struct node *p)
{
	int err;
	struct atom *msgid, *msgdata;

	err = recv_frame_uncompressed(p);

	if (err)
		return -1;

	msgdata = pop();
	msgid = pop();

	recv_hello_data(msgdata);

	free_list(msgid);
	free_list(msgdata);

	return 0;
}

void
recv_hello_data(struct atom *p)
{
//	print_list(p);
	print_client_id(p);
	print_capabilities(p);
}

void
print_client_id(struct atom *p)
{
	int i;

	if (p == NULL || p->cdr == NULL)
		return;

	p = p->cdr->car;

	if (p == NULL || p->length == -1)
		return;

	for (i = 0; i < p->length; i++)
		printf("%c", p->string[i]);

	printf("\n");
}

void
print_capabilities(struct atom *p)
{
	int i, n;
	struct atom *q, *q1, *q2;

	if (p == NULL || p->cdr == NULL || p->cdr->cdr == NULL)
		return;

	p = p->cdr->cdr->car;

	while (p) {

		q = p->car;

		if (q == NULL || q->cdr == NULL)
			return;

		q1 = q->car; // capability
		q2 = q->cdr->car; // version

		if (q1 == NULL || q2 == NULL)
			return;

		if (q1->length < 0 || q2->length < 0)
			return;

		// print capability

		for (i = 0; i < q1->length; i++)
			printf("%c", q1->string[i]);

		printf("/");

		// version

		n = 0;

		for (i = 0; i < q2->length; i++)
			n = 10 * n + q2->string[i];

		printf("%d\n", n);

		p = p->cdr;
	}
}
