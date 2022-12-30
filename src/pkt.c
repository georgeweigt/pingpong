
// packet-data = [version, from, to, expiration, enr-seq ...]
// version = 4
// from = [sender-ip, sender-udp-port, sender-tcp-port]
// to = [recipient-ip, recipient-udp-port, 0]

void
push_ping_packet_data(uint32_t sender_ip, uint32_t recipient_ip)
{
	time_t t;

	t = time(NULL) + 60;

	// version

	push_number(4);

	// from

	push_number(sender_ip);
	push_number(0);
	push_number(0);
	list(3);

	// to

	push_number(recipient_ip);
	push_number(BOOT_PORT);
	push_number(0);
	list(3);

	push_number(t);

	list(3);
}
