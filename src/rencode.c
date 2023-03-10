// recursive length prefix encoder

int
rencode(uint8_t *buf, int len, struct atom *p)
{
	if (rlength(p) > len)
		return 0;
	else
		return rencode_nib(buf, p);
}

int
rencode_nib(uint8_t *buf, struct atom *p)
{
	if (p == NULL || p->length < 0)
		return rencode_list(buf, p);
	else
		return rencode_string(buf, p);
}

int
rencode_list(uint8_t *buf, struct atom *p)
{
	int padlen, sublen;
	uint8_t *t;

	sublen = sublength(p);

	padlen = padlength(p, sublen);

	t = buf + padlen;

	while (p) {
		t += rencode_nib(t, p->car);
		p = p->cdr;
	}

	switch (padlen) {
	case 1:
		buf[0] = 0xc0 + sublen;
		break;
	case 2:
		buf[0] = 0xf7 + 1;
		buf[1] = sublen;
		break;
	case 3:
		buf[0] = 0xf7 + 2;
		buf[1] = sublen >> 8;
		buf[2] = sublen;
		break;
	case 4:
		buf[0] = 0xf7 + 3;
		buf[1] = sublen >> 16;
		buf[2] = sublen >> 8;
		buf[3] = sublen;
		break;
	}

	return padlen + sublen;
}

int
rencode_string(uint8_t *buf, struct atom *p)
{
	int padlen, sublen;

	if (p->length == 1 && p->string[0] < 0x80) {
		buf[0] = p->string[0];
		return 1;
	}

	sublen = p->length;

	padlen = padlength(p, sublen);

	memcpy(buf + padlen, p->string, sublen);

	switch (padlen) {
	case 1:
		buf[0] = 0x80 + sublen;
		break;
	case 2:
		buf[0] = 0xb7 + 1;
		buf[1] = sublen;
		break;
	case 3:
		buf[0] = 0xb7 + 2;
		buf[1] = sublen >> 8;
		buf[2] = sublen;
		break;
	case 4:
		buf[0] = 0xb7 + 3;
		buf[1] = sublen >> 16;
		buf[2] = sublen >> 8;
		buf[3] = sublen;
		break;
	}

	return padlen + sublen;
}
