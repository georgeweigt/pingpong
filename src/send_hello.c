int
send_hello(struct node *p)
{
	int err;
	struct atom *msg_id, *msg_data;

	push_string(NULL, 0); // empty string ""
	msg_id = pop();

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
	msg_data = pop();

	err = send_frame(p, msg_id, msg_data);

	free_list(msg_id);
	free_list(msg_data);

	return err;
}
