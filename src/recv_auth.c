/*	buf contents

	length		2 bytes
	public key	65
	iv		16
	ciphertext	n * 16
	hmac		32
*/

#define R 2
#define IV (2 + 65)
#define C (2 + 65 + 16)
#define D (len - 32)

int
receive_auth(struct node *p, uint8_t *buf, int len)
{
	int err, msglen, pad;
	uint8_t hmac[32], *msg;
	struct atom *list;

	// check length (at least 1 ciphertext block)

	if (len < C + 16 + 32 || (buf[0] << 8 | buf[1]) != len - 2 || (len - 3) % 16) // len - 3 beacuse of R format byte
		return -1;

	// obtain 32 byte shared secret from k * R

	ec_secret(p->shared_secret, p->private_key, buf + R + 1); // R + 1 to skip over format byte

	// derive encryption_key, hmac_key from shared_secret

	kdf(p);

	// check 32 byte hmac

	hmac_sha256(p->hmac_key, 32, buf + IV, D - IV, hmac);
	err = memcmp(hmac, buf + D, 32);
	if (err)
		return -1;

	// decrypt

	aes128_init(p);
	aes128_decrypt(p, buf + IV, (D - IV) / 16);
	msg = buf + C;
	msglen = D - C;
	pad = msg[msglen - 1];
	if (pad > 15)
		return -1;
	msglen = msglen - (pad + 1); // pad length is 1..16 bytes

	err = rdecode_relax(msg, msglen);

	if (err)
		return -1;

	list = pop();

	// save peer public key

	memcpy(p->peer_public_key, list->cdr->car->string, 64);

	free_list(list);

	return 0;
}

#undef R
#undef IV
#undef C
#undef D
