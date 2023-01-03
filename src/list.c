void
list(int n)
{
	int i;
	struct atom *p, *q;

	p = NULL;

	for (i = 0; i < n; i++) {
		q = alloc_atom(-1);
		q->cdr = p;
		q->car = pop();
		p = q;
	}

	push(p);
}

#define STACKSIZE 1000

int atom_count;
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

struct atom *
alloc_atom(int string_length)
{
	struct atom *p;
	p = malloc(sizeof (struct atom) + (string_length > 0 ? string_length : 0));
	if (p == NULL)
		exit(1);
	p->car = NULL;
	p->cdr = NULL;
	p->length = string_length;
	atom_count++;
	return p;
}

void
free_list(struct atom *p)
{
	struct atom *t;

	if (p == NULL)
		return;

	if (p->length < 0)
		while (p) {
			t = p->cdr;
			free_list(p->car);
			free(p);
			atom_count--;
			p = t;
		}
	else {
		free(p);
		atom_count--;
	}
}

// returns 0 for equal

int
compare_lists(struct atom *p, struct atom *q)
{
	int d;

	if (p == NULL && q == NULL)
		return 0;

	if (p == NULL && q != NULL)
		return -1;

	if (p != NULL && q == NULL)
		return 1;

	if (p->length == -1 && q->length == -1) {
		while (p && q) {
			d = compare_lists(p->car, q->car);
			if (d)
				return d;
			p = p->cdr;
			q = q->cdr;
		}
		return compare_lists(p, q);
	}

	if (p->length < q->length)
		return -1;

	if (p->length > q->length)
		return 1;

	return memcmp(p->string, q->string, p->length);
}
