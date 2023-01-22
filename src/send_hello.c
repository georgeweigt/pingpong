int
send_hello(struct node *p)
{
	int err;
	struct atom *msgid, *msgdata;

	push_string(NULL, 0); // empty string ""
	msgid = pop();

	// msg data

	push_number(5); // protocol version 5

	push_string((uint8_t *) "pingpong", 3); // client software

	push_string((uint8_t *) "eth", 3); // capability
	push_number(67);
	list(2);
	list(1); // [ ["eth",67] ]

	push_string(NULL, 0); // listen port

	push_string(p->public_key, 64); // public key

	list(5);
	msgdata = pop();

	err = send_frame_uncompressed(p, msgid, msgdata);

	free_list(msgid);
	free_list(msgdata);

	return err;
}
