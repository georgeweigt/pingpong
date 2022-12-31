int
encode(uint8_t *outbuf, struct atom *p)
{
	if (p->car)
		return encode_list(outbuf, p);
	else
		return encode_string(outbuf, p);
}

int
encode_list(uint8_t *outbuf, struct atom *p)
{
	int padlen, sublen;
	uint8_t *t;

	sublen = sublength(p);

	padlen = padlength(p, sublen);

	t = outbuf + padlen;

	while (p) {
		t += encode(t, p->car);
		p = p->cdr;
	}

	switch (padlen) {
	case 1:
		outbuf[0] = 0xc0 + sublen;
		break;
	case 2:
		outbuf[0] = 0xf7 + 1;
		outbuf[1] = sublen;
		break;
	case 3:
		outbuf[0] = 0xf7 + 2;
		outbuf[1] = sublen >> 8;
		outbuf[2] = sublen;
		break;
	case 4:
		outbuf[0] = 0xf7 + 3;
		outbuf[1] = sublen >> 16;
		outbuf[2] = sublen >> 8;
		outbuf[3] = sublen;
		break;
	}

	return padlen + sublen;
}

int
encode_string(uint8_t *outbuf, struct atom *p)
{
	int padlen, sublen;

	if (p->length == 1 && p->string[0] < 0x80) {
		outbuf[0] = p->string[0];
		return 1;
	}

	sublen = p->length;

	padlen = padlength(p, sublen);

	memcpy(outbuf + padlen, p->string, sublen);

	switch (padlen) {
	case 1:
		outbuf[0] = 0x80 + sublen;
		break;
	case 2:
		outbuf[0] = 0xb7 + 1;
		outbuf[1] = sublen;
		break;
	case 3:
		outbuf[0] = 0xb7 + 2;
		outbuf[1] = sublen >> 8;
		outbuf[2] = sublen;
		break;
	case 4:
		outbuf[0] = 0xb7 + 3;
		outbuf[1] = sublen >> 16;
		outbuf[2] = sublen >> 8;
		outbuf[3] = sublen;
		break;
	}

	return padlen + sublen;
}
