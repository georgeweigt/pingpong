// hdr		2 bytes
// public key	65 bytes
// iv		16 bytes
// ciphertext	msglen bytes
// hmac		32 bytes

#define R 2
#define IV (2 + 65)
#define C (2 + 65 + 16)

int
receive_auth(struct node *p, uint8_t *buf, int len)
{
	int err, msglen;
	uint8_t hmac[32];
	struct atom *list;

	msglen = len - 2 - 65 - 16 - 32; // hdr, R, iv, hmac

	// check length

	if (msglen < 0 || (buf[0] << 8 | buf[1]) != len - 2)
		return -1;

	// derive ephemeral_shared_secret from private_key and R

	ec_ecdh(p->ephemeral_shared_secret, p->private_key, buf + R + 1); // R + 1 to skip over format byte

	// derive aes_key and hmac_key from ephemeral_shared_secret

	kdf(p->aes_key, p->hmac_key, p->ephemeral_shared_secret);

	// check hmac

	hmac_sha256(p->hmac_key, 32, buf + IV, msglen + 16, hmac);
	err = memcmp(hmac, buf + len - 32, 32);
	if (err)
		return -1;

	// decrypt

	aes128ctr_keyinit(p, buf + IV);
	aes128ctr_encrypt(p, buf + C, msglen);

	err = rdecode_relax(buf + C, msglen);

	if (err)
		return -1;

	list = pop();

	// FIXME validate list
#if 0
	printf("%d bytes\n", list->car->length);
	printmem(list->car->string, list->car->length);

	printf("%d bytes\n", list->cdr->car->length);
	printmem(list->cdr->car->string, list->cdr->car->length);

	printf("%d bytes\n", list->cdr->cdr->car->length);
	printmem(list->cdr->cdr->car->string, list->cdr->cdr->car->length);

	printf("%d bytes\n", list->cdr->cdr->cdr->car->length);
	printmem(list->cdr->cdr->cdr->car->string, list->cdr->cdr->cdr->car->length);
#endif
	// save peer public key

	memcpy(p->peer_public_key, list->cdr->car->string, 64);

	free_list(list);

	return 0;
}

#undef R
#undef IV
#undef C
