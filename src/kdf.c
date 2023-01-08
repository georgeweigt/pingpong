// key derivation function

void
kdf(struct node *p)
{
	uint8_t buf[36];

	// big endian counter = 1

	buf[0] = 0;
	buf[1] = 0;
	buf[2] = 0;
	buf[3] = 1;

	memcpy(buf + 4, p->shared_secret, 32);

	sha256(buf, 36, buf);

	// first 16 bytes are the AES key

	memcpy(p->encryption_key, buf, 16);

	// hash last 16 bytes to get 32 byte HMAC key

	sha256(buf + 16, 16, buf);

	memcpy(p->hmac_key, buf, 32);
}
