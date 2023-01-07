struct atom *
auth_body(struct node *p)
{
	uint8_t sig[32];

	// sig

	keccak256(sig, p->ephemeral_public_key, 64);
	push_string(sig, 32);

	// initiator public key

	push_string(p->public_key, 64);

	// initiator nonce

	push_string(p->nonce, 32);

	// auth version

	push_number(4);

	list(4);

	return pop();
}
