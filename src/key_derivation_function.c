/* from crypto.py in pydevp2p

def eciesKDF(key_material, key_len):
    """
    interop w/go ecies implementation

    for sha3, blocksize is 136 bytes
    for sha256, blocksize is 64 bytes

    NIST SP 800-56a Concatenation Key Derivation Function (see section 5.8.1).
    """
    s1 = b""
    key = b""
    hash_blocksize = 64
    reps = ((key_len + 7) * 8) / (hash_blocksize * 8)
    counter = 0
    while counter <= reps:
        counter += 1
        ctx = sha256()
        ctx.update(struct.pack('>I', counter))
        ctx.update(key_material)
        ctx.update(s1)
        key += ctx.digest()
    return key[:key_len]
*/

void
key_derivation_function(struct session *s)
{
	uint8_t inbuf[36], outbuf[32];

	inbuf[0] = 1; // counter = 1
	inbuf[1] = 0;
	inbuf[2] = 0;
	inbuf[3] = 0;

	memcpy(inbuf + 4, s->shared_secret, 32);

	sha256(inbuf, 36, outbuf);

	memcpy(s->encryption_key, outbuf, 16);
	memcpy(s->mac_key, outbuf + 16, 16);
}
