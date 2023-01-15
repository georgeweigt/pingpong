void
macs(struct node *p)
{
	int i;
	uint8_t buf[32];

	// ingress-mac = keccak256.init((mac-secret ^ initiator-nonce) || ack)

	for (i = 0; i < 32; i++)
		buf[i] = p->mac_secret[i] ^ p->auth_nonce[i];

	keccak256_init(&p->ingress_mac);
	keccak256_update(&p->ingress_mac, buf, 32);
	keccak256_update(&p->ingress_mac, p->ack_buf, p->ack_len);

	// egress-mac = keccak256.init((mac-secret ^ recipient-nonce) || auth)

	for (i = 0; i < 32; i++)
		buf[i] = p->mac_secret[i] ^ p->ack_nonce[i];

	keccak256_init(&p->egress_mac);
	keccak256_update(&p->egress_mac, buf, 32);
	keccak256_update(&p->egress_mac, p->auth_buf, p->auth_len);
}
