uint8_t *
encryptmsg(struct session *s, uint8_t *msg, int len, int *plen)
{
	generate_ephemeral_keyset(s);

	return NULL;
}
