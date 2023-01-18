int
send_disconnect(struct node *p)
{
	int err;
	struct atom *msg_id, *msg_data;

	push_number(1); // disconnect
	msg_id = pop();

	push_number(0); // reason
	list(1);
	msg_data = pop();

	err = send_frame(p, msg_id, msg_data);

	free_list(msg_id);
	free_list(msg_data);

	return err;
}
