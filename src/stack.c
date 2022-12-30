#define STACKSIZE 1000

int tos;
struct atom *stack[STACKSIZE];

void
push(struct atom *p)
{
	if (tos == STACKSIZE) {
		printf("stack overrun\n");
		exit(1);
	}

	stack[tos++] = p;
}

struct atom *
pop(void)
{
	if (tos == 0) {
		printf("stack underrun\n");
		exit(1);
	}

	return stack[--tos];
}

void
push_number(uint64_t n)
{
	int i, k, len;
	uint8_t buf[8];
	struct atom *p;

	buf[0] = n >> 56;
	buf[1] = n >> 48;
	buf[2] = n >> 40;
	buf[3] = n >> 32;
	buf[4] = n >> 24;
	buf[5] = n >> 16;
	buf[6] = n >> 8;
	buf[7] = n;

	for (k = 0; k < 7; k++)
		if (buf[k])
			break;

	len = 8 - k;

	p = alloc_atom(len);

	for (i = 0; i < len; i++)
		p->string[i] = buf[k + i];

	push(p);
}

void
list(int n)
{
	int i;
	struct atom *p, *q;

	p = NULL;

	for (i = 0; i < n; i++) {
		q = alloc_atom(0);
		q->cdr = p;
		q->car = pop();
		p = q;
	}

	push(p);
}

struct atom *
alloc_atom(int string_length)
{
	struct atom *p;
	p = malloc(sizeof (struct atom) + string_length);
	if (p == NULL)
		exit(1);
	p->car = NULL;
	p->cdr = NULL;
	p->length = string_length;
	return p;
}
