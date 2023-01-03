int
enlength(struct atom *p)
{
	int len = sublength(p);
	return padlength(p, len) + len;
}

int
sublength(struct atom *p)
{
	int len;

	if (p == NULL)
		return 0;

	if (p->length < 0) {

		len = 0;

		while (p) {
			len += enlength(p->car);
			p = p->cdr;
		}

		return len;
	} else
		return p->length;
}

int
padlength(struct atom *p, int sublen)
{
	if (p == NULL)
		return 1;

	if (p->length == 1 && p->string[0] < 0x80)
		return 0;

	if (sublen < 56)
		return 1;

	if (sublen < 256)
		return 2;

	if (sublen < 65536)
		return 3;

	return 4;
}
