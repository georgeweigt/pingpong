uint8_t *
decompress(uint8_t *inbuf, int inlength, int *plen)
{
	int len, outlength;
	uint8_t *outbuf;

	outlength = decompress_length(inbuf, inlength, NULL);

	// sanity check

	if (outlength < 1 || outlength > 64 * inlength) {
		trace();
		return NULL;
	}

	outbuf = alloc_mem(outlength);

	if (outbuf == NULL) {
		trace();
		return NULL;
	}

	len = decompress_nib(outbuf, outlength, inbuf, inlength);

	if (len != outlength) {
		trace();
		free_mem(outbuf);
		return NULL;
	}

	*plen = len;

	return outbuf;
}

#define I (inbuf + inindex)

int
decompress_nib(uint8_t *outbuf, int outmax, uint8_t *inbuf, int inlength)
{
	int len, off, inindex, outindex, outlength;
	uint64_t u;

	outlength = decompress_length(inbuf, inlength, &inindex);

	// sanity check

	if (outlength < 1 || outlength > outmax)
		return 0; // err

	outindex = 0;

	while (inindex < inlength) {

		if ((I[0] & 0x03) == 0x00) {

			// literal

			switch (I[0] >> 2) {

			case 60: // 1 length byte

				if (inindex + 2 > inlength)
					return 0; // err

				len = I[1] + 1;

				inindex += 2;

				break;

			case 61: // 2 length bytes

				if (inindex + 3 > inlength)
					return 0; // err

				len = (I[2] << 8 | I[1]) + 1;

				inindex += 3;

				break;

			case 62: // 3 length bytes

				if (inindex + 4 > inlength)
					return 0; // err

				len = (I[3] << 16 | I[2] << 8 | I[1]) + 1;

				inindex += 4;

				break;

			case 63: // 4 length bytes

				if (inindex + 5 > inlength)
					return 0; // err

				u = (uint64_t) (I[4] << 24 | I[3] << 16 || I[2] << 8 | I[1]) + 1;

				if (u > 0x7fffffff)
					return 0; // err

				len = u;

				inindex += 5;

				break;

			default: // 1 to 60 bytes

				len = (I[0] >> 2) + 1;
				inindex++;

				break;
			}

			if (inindex + len > inlength || outindex + len > outlength)
				return 0; // err

			memcpy(outbuf + outindex, inbuf + inindex, len);

			inindex += len;
			outindex += len;

		} else {

			// copy

			switch (I[0] & 0x03) {

			case 0x01:

				// 1 byte offset

				if (inindex + 2 > inlength)
					return 0; // err

				off = (I[0] << 3 & 0x700) | I[1];
				len = (I[0] >> 2 & 0x07) + 4;

				inindex += 2;

				break;

			case 0x02:

				// 2 byte offset

				if (inindex + 3 > inlength)
					return 0; // err

				off = I[2] << 8 | I[1];
				len = (I[0] >> 2) + 1;

				inindex += 3;

				break;

			case 0x03:

				// 4 byte offset

				if (inindex + 5 > inlength)
					return 0; // err

				u = (uint64_t) (I[4] << 24 | I[3] << 16 | I[2] << 8 | I[1]) + 1;

				if (u > 0xffff)
					return 0; // err

				off = u;
				len = (I[0] >> 2) + 1;

				inindex += 5;

				break;
			}

			if (off < 1 || off > outindex || outindex + len > outlength)
				return 0; // err

			while (len > off) {
				memcpy(outbuf + outindex, outbuf + outindex - off, off);
				outindex += off;
				len -= off;
			}

			memcpy(outbuf + outindex , outbuf + outindex - off, len);

			outindex += len;
		}
	}

	if (outindex < outlength)
		return 0; // err

	return outlength;
}

// returns length from inbuf

int
decompress_length(uint8_t *inbuf, int inlength, int *inindex)
{
	int i, k;
	uint64_t u;

	// advance to end of length field

	k = 0;

	while (k < inlength && (inbuf[k] & 0x80))
		k++;

	if (k == inlength)
		return 0; // err

	// compute length

	u = 0;

	for (i = k; i >= 0; i--) {

		u = (u << 7) | (inbuf[i] & 0x7f);

		if (u > 0x7fffffff)
			return 0; // err
	}

	if (inindex)
		*inindex = k + 1;

	return (int) u;
}
