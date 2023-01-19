// snappy compress

uint8_t *
compress(uint8_t *inbuf, int inlength, int *plen)
{
	struct compress_state state;

	// init

	state.inbuf = inbuf;
	state.inindex = 0;
	state.inlength = inlength;

	state.outlength = inlength + 16;
	state.outbuf = malloc(state.outlength);
	if (state.outbuf == NULL)
		exit(1);
	state.outindex = 0;

	// emit length

	while (inlength > 128) {
		state.outbuf[state.outindex++] = (inlength % 128) | 0x80;
		inlength /= 128;
	}

	state.outbuf[state.outindex++] = inlength;

	// compress

	for (;;) {
		compress_emit_literal(&state);
		if (state.inindex == state.inlength)
			break;
		compress_emit_copy(&state);
		if (state.inindex == state.inlength)
			break;
	}

	*plen = state.outindex;

	return state.outbuf;
}

void
compress_emit_literal(struct compress_state *p)
{
	int k, len;

	k = p->inindex;

	while (p->inindex < p->inlength) {
		if (compress_match(p))
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

int
compress_match(struct compress_state *p)
{
	int len, offset;

	offset = p->inindex; // offset is how far to go back to find a match

	if (offset > 0xffff)
		offset = 0xffff;

	while (offset > 0) {

		len = compress_match_length(p, offset);

		if (len) {
			p->match_offset = offset;
			p->match_length = len;
			return 1;
		}

		offset--;
	}

	return 0;
}

// returns length of match

int
compress_match_length(struct compress_state *p, int offset)
{
	int len, n;
	uint8_t *s, *t;

	t = p->inbuf + p->inindex;
	s = t - offset;

	n = p->inlength - p->inindex; // number of bytes to match

	if (n > 64)
		n = 64;

	for (len = 0; len < n; len++)
		if (s[len] != t[len])
			break;

	return len;
}

void
compress_emit_copy(struct compress_state *p)
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
compress_emit_byte(struct compress_state *p, uint32_t c)
{
	if (p->outindex == p->outlength) {
		p->outlength++;
		p->outbuf = realloc(p->outbuf, p->outlength);
		if (p->outbuf == NULL)
			exit(1);
	}
	p->outbuf[p->outindex++] = c;
}

void
compress_emit_mem(struct compress_state *p, int index, int len)
{
	if (p->outindex + len > p->outlength) {
		p->outlength += len;
		p->outbuf = realloc(p->outbuf, p->outlength);
		if (p->outbuf == NULL)
			exit(1);
	}

	memcpy(p->outbuf + p->outindex, p->inbuf + index, len);

	p->outindex += len;
}
