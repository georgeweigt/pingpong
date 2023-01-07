uint8_t *
create_auth_message(struct node *p, int *plen)
{
	push_string(p->public_key, 64);
	push_string(p->nonce, 32);
	push_number(4); // auth version

	return NULL;
}
