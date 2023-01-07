int
receive_auth(struct node *p, uint8_t *buf, int len)
{
	int err;
	uint8_t hmac[32];

	// check length (2 + 64 + 16 + 16 + 32 = 130)

	if (len < 130 || (buf[0] << 8 | buf[1]) != len - 2)
		return -1;

	// obtain 32 byte shared secret from k * R

	ec_secret(p->shared_secret, p->private_key, buf + 2);

	kdf(p); // returns hmac_key, encryption_key

	hmac_sha256(p->hmac_key, 16, buf + 66, len - 98, hmac);

	// check hmac

	err = memcmp(hmac, buf + len - 32, 32);

	if (err)
		return -1;

	return 0;
}
