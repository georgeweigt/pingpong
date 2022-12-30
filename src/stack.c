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
push_string(uint8_t *string, int length)
{
	struct atom *p;
	p = alloc_atom(length);
	memcpy(p->string, string, length);
	push(p);
}

void
push_number(uint64_t n)
{
	int i;
	uint8_t buf[8];

	buf[0] = n >> 56;
	buf[1] = n >> 48;
	buf[2] = n >> 40;
	buf[3] = n >> 32;
	buf[4] = n >> 24;
	buf[5] = n >> 16;
	buf[6] = n >> 8;
	buf[7] = n;

	for (i = 0; i < 7; i++)
		if (buf[i])
			break;

	push_string(buf + i, 8 - i);
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
