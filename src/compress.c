// snappy compression

#define MIN_LENGTH 4 // match lengths less than this do not trigger a copy
#define MAX_OFFSET 1000 // how far back to search, shorter = faster

int
compress(uint8_t *outbuf, int outmax, uint8_t *inbuf, int inlength)
{
	struct compress_state_t s;

	// init state

	s.inbuf = inbuf;
	s.inindex = 0;
	s.inlength = inlength;

	s.outbuf = outbuf;
	s.outindex = 0;
	s.outmax = outmax;

	// emit length

	while (inlength >= 128) {
		compress_emit_byte(&s, (inlength % 128) | 0x80);
		inlength /= 128;
	}

	compress_emit_byte(&s, inlength);

	// compress

	for (;;) {
		compress_emit_literal(&s);
		if (s.inindex == s.inlength)
			break;
		compress_emit_copy(&s);
		if (s.inindex == s.inlength)
			break;
	}

	if (s.outindex > s.outmax)
		s.outindex = 0; // buffer overrun

	return s.outindex;
}

void
compress_emit_literal(struct compress_state_t *p)
{
	int k, len;

	k = p->inindex;

	while (p->inindex < p->inlength) {
		compress_match(p);
		if (p->match_length > 0)
			break;
		p->inindex++;
	}

	len = p->inindex - k;

	if (len == 0)
		return;

	// emit literal string

	if (len <= 60)
		compress_emit_byte(p, (len - 1) << 2);
	else if (len <= 0x100) {
		compress_emit_byte(p, 60 << 2);
		compress_emit_byte(p, len - 1);
	} else if (len <= 0x10000) {
		compress_emit_byte(p, 61 << 2);
		compress_emit_byte(p, len - 1);
		compress_emit_byte(p, (len - 1) >> 8);
	} else if (len <= 0x1000000) {
		compress_emit_byte(p, 62 << 2);
		compress_emit_byte(p, len - 1);
		compress_emit_byte(p, (len - 1) >> 8);
		compress_emit_byte(p, (len - 1) >> 16);
	} else {
		compress_emit_byte(p, 63 << 2);
		compress_emit_byte(p, len - 1);
		compress_emit_byte(p, (len - 1) >> 8);
		compress_emit_byte(p, (len - 1) >> 16);
		compress_emit_byte(p, (len - 1) >> 24);
	}

	compress_emit_mem(p, k, len);
}

void
compress_match(struct compress_state_t *p)
{
	int len, offset;

	p->match_length = 0;

	offset = 1;

	while (offset <= p->inindex && offset <= MAX_OFFSET) {

		len = compress_match_length(p, offset);

		if (len >= MIN_LENGTH && len > p->match_length) {
			p->match_offset = offset;
			p->match_length = len;
			if (len == 64)
				return; // snappy max length is 64
		}

		offset++;
	}
}

// returns length of match

int
compress_match_length(struct compress_state_t *p, int offset)
{
	int i, j, k;

	j = p->inindex;

	k = p->inindex + 64;

	if (k > p->inlength)
		k = p->inlength;

	for (i = j; i < k; i++)
		if (p->inbuf[i - offset] != p->inbuf[i])
			break;

	return i - j;
}

void
compress_emit_copy(struct compress_state_t *p)
{
	int len, off;

	off = p->match_offset;
	len = p->match_length;

	if (len >= 4 && len <= 11 && off < 2048) {
		compress_emit_byte(p, (off >> 3 & 0xe0) | (len - 4) << 2 | 0x01);
		compress_emit_byte(p, off);
	} else {
		compress_emit_byte(p, (len - 1) << 2 | 0x02);
		compress_emit_byte(p, off);
		compress_emit_byte(p, off >> 8);
	}

	p->inindex += len;
}

void
compress_emit_byte(struct compress_state_t *p, uint32_t c)
{
	if (p->outindex + 1 <= p->outmax)
		p->outbuf[p->outindex] = c;
	p->outindex++;
}

void
compress_emit_mem(struct compress_state_t *p, int k, int len)
{
	if (p->outindex + len <= p->outmax)
		memcpy(p->outbuf + p->outindex, p->inbuf + k, len);
	p->outindex += len;
}
