
// packet-data = [version, from, to, expiration, enr-seq ...]
// version = 4
// from = [sender-ip, sender-udp-port, sender-tcp-port]
// to = [recipient-ip, recipient-udp-port, 0]

void
push_ping_packet_data(uint8_t *sender_ip, uint8_t *recipient_ip)
{
	time_t t;

	t = time(NULL) + 60;

	// version

	push_number(4);

	// from

	push_string(sender_ip, 4);
	push_number(0);
	push_number(0);
	list(3); // [sender-ip, sender-udp-port, sender-tcp-port]

	// to

	push_string(recipient_ip, 4);
	push_number(BOOT_PORT);
	push_number(0);
	list(3); // [recipient-ip, recipient-udp-port, 0]

	// expiration

	push_number(t);

	list(4); // [version, from, to, expiration]
}
