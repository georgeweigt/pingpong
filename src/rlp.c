#include "defs.h"

int
rlp_encode(uint8_t *outbuf, struct atom *p)
{
	if (p->car)
		return rlp_encode_list(outbuf, p);
	else
		return rlp_encode_string(outbuf, p);
}

int
rlp_encode_list(uint8_t *outbuf, struct atom *p)
{
	int h, len;
	uint8_t *t;

	len = rlp_length(p, 0);

	if (len > 65535)
		h = 4;
	else if (len > 255)
		h = 3;
	else if (len > 55)
		h = 2;
	else
		h = 1;

	t = outbuf;

	outbuf += h;

	while (p) {
		outbuf += rlp_encode(outbuf, p->car);
		p = p->cdr;
	}

	outbuf = t;

	switch (h) {
	case 1:
		outbuf[0] = 0xc0 + len;
		break;
	case 2:
		outbuf[0] = 0xf7 + 1;
		outbuf[1] = len;
		break;
	case 3:
		outbuf[0] = 0xf7 + 2;
		outbuf[1] = len >> 8;
		outbuf[2] = len;
		break;
	case 4:
		outbuf[0] = 0xf7 + 3;
		outbuf[1] = len >> 16;
		outbuf[2] = len >> 8;
		outbuf[3] = len;
		break;
	}

	return h + len;
}

int
rlp_encode_string(uint8_t *outbuf, struct atom *p)
{
	int h, len;

	len = p->length;

	if (len == 1) {
		outbuf[0] = p->string[0];
		return 1;
	}

	if (len > 65535)
		h = 4;
	else if (len > 255)
		h = 3;
	else if (len > 55)
		h = 2;
	else
		h = 1;

	memcpy(outbuf + h, p->string, len);

	switch (h) {
	case 1:
		outbuf[0] = 0x80 + len;
		break;
	case 2:
		outbuf[0] = 0xb7 + 1;
		outbuf[1] = len;
		break;
	case 3:
		outbuf[0] = 0xb7 + 2;
		outbuf[1] = len >> 8;
		outbuf[2] = len;
		break;
	case 4:
		outbuf[0] = 0xb7 + 3;
		outbuf[1] = len >> 16;
		outbuf[2] = len >> 8;
		outbuf[3] = len;
		break;
	}

	return h + len;
}

// level == 0 returns raw length (no header)

int
rlp_length(struct atom *p, int level)
{
	int h, len;

	if (p->car) {

		len = 0;

		while (p) {
			len += rlp_length(p->car, 1);
			p = p->cdr;
		}

	} else {

		len = p->length;

		if (len == 1)
			return 1;
	}

	if (level == 0)
		return len;

	if (len > 65535)
		h = 4;
	else if (len > 255)
		h = 3;
	else if (len > 55)
		h = 2;
	else
		h = 1;

	return h + len;
}

void
rlp_decode(struct atom *p)
{
}
