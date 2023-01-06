uint8_t *
encryptmsg(struct session *s, uint8_t *msg, int len, int *plen)
{
	int i;

	generate_ephemeral_keyset(s);
	key_derivation_function(s);

	for (i = 0; i < 16; i++)
		s->iv[i] = random();

	return NULL; // stub
}
