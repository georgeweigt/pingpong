// returns 0 ok, -1 err

int
recv_status(struct node *p)
{
	int err;
	struct atom *msgid, *msgdata;

	err = recv_frame(p);

	if (err) {
		trace();
		return -1;
	}

	msgdata = pop();
	msgid = pop();

	print_list(msgid);
	print_list(msgdata);

	free_list(msgid);
	free_list(msgdata);

	return 0;
}
