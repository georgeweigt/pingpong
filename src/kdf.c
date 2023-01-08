// aes_key		16 bytes (result)
// hmac_key		32 bytes (result)
// shared_secret	32 bytes

void
kdf(uint8_t *aes_key, uint8_t *hmac_key, uint8_t *shared_secret)
{
	uint8_t buf[36];

	// big endian counter = 1

	buf[0] = 0;
	buf[1] = 0;
	buf[2] = 0;
	buf[3] = 1;

	memcpy(buf + 4, shared_secret, 32);

	// hash from first buf to second buf

	sha256(buf, 36, buf);

	// first 16 bytes are the AES key

	memcpy(aes_key, buf, 16);

	// hash last 16 bytes to get 32 byte HMAC key

	sha256(buf + 16, 16, buf);

	memcpy(hmac_key, buf, 32);
}
