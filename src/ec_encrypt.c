/*
Encrypted message is

	0x04 || R || iv || c || d

where

	R	ephemeral public key (64 bytes)
	iv	initialization vector (16 bytes)
	c	ciphertext
	d	hmac (32 bytes)
*/

#define R hdrlen
#define IV (hdrlen + 65)
#define C (hdrlen + 65 + 16)
#define D (len - 32)

uint8_t *
ec_encrypt(struct node *p, uint8_t *msg, int msglen, int hdrlen, int *plen)
{
	int i, len;
	uint8_t *buf;

	// generate ephemeral_private_key and ephemeral_public_key

	ec_genkey(p->ephemeral_private_key, p->ephemeral_public_key);

	// derive shared_secret from ephemeral_private_key and peer_public_key

	ec_ecdh(p->shared_secret, p->ephemeral_private_key, p->peer_public_key);

	// derive AES and HMAC keys from shared_secret

	kdf(p->aes_key, p->hmac_key, p->shared_secret);

	// get malloc'd buffer

	len = C + msglen + 32;
	buf = malloc(len);
	if (buf == NULL)
		exit(1);

	// ephemeral key R

	buf[R] = 0x04; // uncompressed format
	memcpy(buf + R + 1, p->ephemeral_public_key, 64);

	// iv

	for (i = 0; i < 16; i++)
		buf[IV + i] = random();

	// encrypt the message

	memcpy(buf + C, msg, msglen);
	aes128ctr_keyinit(p, buf + IV);
	aes128ctr_encrypt(p, buf + C, msglen);

	// compute hmac over IV and C (length is D - IV bytes)

	hmac_sha256(p->hmac_key, 32, buf + IV, D - IV, buf + D);

	*plen = len;
	return buf;
}

#undef R
#undef IV
#undef C
#undef D
