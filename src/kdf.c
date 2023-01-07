// key derivation function

void
kdf(struct node *p)
{
	uint8_t inbuf[36], outbuf[32];

	inbuf[0] = 0; // counter = 1 in big endian
	inbuf[1] = 0;
	inbuf[2] = 0;
	inbuf[3] = 1;

	memcpy(inbuf + 4, p->shared_secret, 32);

	sha256(inbuf, 36, outbuf);

	memcpy(p->encryption_key, outbuf, 16);
	memcpy(p->hmac_key, outbuf + 16, 16);
}
