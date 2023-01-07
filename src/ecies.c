/* Elliptic Curve Integrated Encryption Scheme

Encrypted message is

	R || iv || c || d

where

	R	ephemeral public key (64 bytes)
	iv	initialization vector (16 bytes)
	c	ciphertext (multiple of 16 bytes)
	d	hmac (32 bytes)
*/

uint8_t *
ecies_encrypt(struct node *p, uint8_t *msg, int msglen, int *plen)
{
	int i, n, len, pad;
	uint8_t *buf;

	geneph(p); // generate ephemeral keyset
	kdf(p); // key derivation function
	aes128_init(p);

	// get buffer

	n = (msglen + 1 + 15) / 16; // n is number of blocks (msglen + 1 for minimum pad)
	len = 64 + 16 * (n + 1) + 32; // n + 1 for iv
	buf = malloc(len);
	if (buf == NULL)
		exit(1);

	// ephemeral key R

	memcpy(buf, p->ephemeral_public_key, 64);

	// iv

	for (i = 0; i < 16; i++)
		buf[64 + i] = random();

	// encrypted message

	memcpy(buf + 80, msg, msglen);

	// pad last block

	pad = 15 - (msglen & 0xf); // pad byte value (0..15)
	memset(buf + 80 + msglen, pad, pad + 1); // 1..16 bytes are set with pad value

	aes128_encrypt(p, buf + 64, n + 1); // n + 1 for iv

	// hmac

	hmac_sha256(p->hmac_key, 16, buf + 64, 16 * (n + 1), buf + len - 32);

	*plen = len;
	return buf;
}
