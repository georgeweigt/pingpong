/* buf contents

	length		2 bytes
	public key	64
	iv		16
	ciphertext	n * 16
	hmac		32
*/

int
receive_auth(struct node *p, uint8_t *buf, int len)
{
	int err, msglen, pad;
	uint8_t hmac[32], *msg;
	struct atom *list;

	// check length (2 + 64 + 16 + 16 + 32 = 130)

	if (len < 130 || (buf[0] << 8 | buf[1]) != len - 2 || (len - 2) % 16)
		return -1;

	// obtain 32 byte shared secret from k * R

	ec_secret(p->shared_secret, p->private_key, buf + 2);

	// derive encryption_key, hmac_key from shared_secret

	kdf(p);

	// check hmac

	hmac_sha256(p->hmac_key, 16, buf + 66, len - 98, hmac);
	err = memcmp(hmac, buf + len - 32, 32);
	if (err)
		return -1;

	// decrypt

	aes128_init(p);
	aes128_decrypt(p, buf + 66, (len - 98) / 16);
	msg = buf + 82;
	msglen = len - 114;
	pad = msg[msglen - 1];
	if (pad > 15)
		return -1;
	msglen = msglen - (pad + 1); // pad length is 1..16 bytes

	err = decode(msg, msglen);

	if (err)
		return -1;

	list = pop();

	// save peer public key

	memcpy(p->peer_public_key, list->cdr->car->string, 64);

	free_list(list);

	return 0;
}
