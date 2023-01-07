void
receive_auth(struct node *p, uint8_t *buf, int len)
{
	int err;
	uint8_t hmac[32];

	// obtain 32 byte shared secret from k * R

	ec_secret(p->shared_secret, p->private_key, buf + 2);

	kdf(p); // returns hmac_key, encryption_key

	hmac_sha256(p->hmac_key, 16, buf + 66, len - 98, hmac);

	printf("checking shared secret ");
	err = memcmp(initiator.shared_secret, recipient.shared_secret, 32);
	printf("%s\n", err ? "err" : "ok");

	printf("checking hmac ");
	err = memcmp(hmac, buf + len - 32, 32);
	printf("%s\n", err ? "err" : "ok");
}
