int
send_hello(struct node *p)
{
	int err;
	struct atom *msgid, *msgdata;

	// msg id

	push_string(NULL, 0); // empty string ""
	msgid = pop();

	// msg data

	// protocol version 5

	push_number(5);

	// client software

	push_string((uint8_t *) "pingpong", 3);

	// capability (eth/67)
#if 1
	push_string((uint8_t *) "eth", 3);
	push_number(67);
	list(2);
	list(1); // [ ["eth",67] ]
#else
	list(0); // empty list [], no capability, geth prints 'useless peer'
#endif

	// listen port (none)

	push_string(NULL, 0);

	// public key

	push_string(p->public_key, 64);

	list(5);
	msgdata = pop();

	err = send_frame_uncompressed(p, msgid, msgdata);

	free_list(msgid);
	free_list(msgdata);

	return err;
}
