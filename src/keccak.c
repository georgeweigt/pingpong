// Keccak-256 (see Table 3 on page 22 of FIPS PUB 202 for rate and capacity)
//
// Rate		r = 1088 bits (136 bytes)
//
// Capacity	c = 512 bits (64 bytes)

#define RATE 136
#define A(x,y,z) A[320 * (x) + 64 * (y) + (z)]
#define Aprime(x,y,z) Aprime[320 * (x) + 64 * (y) + (z)]

uint8_t RC[64][24]; // round constants (24 rounds)

void
keccak_init(void)
{
	int i, j;
	for (i = 0; i < 24; i++)
		for (j = 0; j < 7; j++)
			RC[(1 << j) - 1][i] = rc(j + 7 * i);
}

int
rc(int t)
{
	int i;
	uint32_t R;

	if (t % 255 == 0)
		return 1;

	R = 1;

	for (i = 1; i <= t % 255; i++) {

		R <<= 1;

		if (R & 0x100)
			R ^= 0x171;
	}

	return R & 1;
}

uint8_t *
theta(uint8_t *A)
{
	int x, y, z;
	static uint8_t Aprime[1600], C[5][64], D[5][64];

	for (x = 0; x < 5; x++)
		for (z = 0; z < 64; z++)
			C[x][z] = A(x,0,z) ^ A(x,1,z) ^ A(x,2,z) ^ A(x,3,z) ^ A(x,4,z);

	for (x = 0; x < 5; x++)
		for (z = 0; z < 64; z++)
			D[x][z] = C[(5 + x - 1) % 5][z] ^ C[(x + 1) % 5][(64 + z - 1) % 64];

	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			for (z = 0; z < 64; z++)
				Aprime(x,y,z) = A(x,y,z) ^ D[x][z];

	return Aprime;
}

uint8_t *
rho(uint8_t *A)
{
	int t, u, x, y, z;
	static uint8_t Aprime[1600];

	for (z = 0; z < 64; z++)
		Aprime(0,0,z) = A(0,0,z);

	x = 1;
	y = 0;

	for (t = 0; t < 24; t++) {
		for (z = 0; z < 64; z++)
			Aprime(x,y,z) = A(x,y,(320 + z - (t + 1) * (t + 2) / 2) % 64);
		u = y;
		y = (2 * x + 3 * y) % 5;
		x = u;
	}

	return Aprime;
}

uint8_t *
pi(uint8_t *A)
{
	int x, y, z;
	static uint8_t Aprime[1600];

	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			for (z = 0; z < 64; z++)
				Aprime(x,y,z) = A((x + 3 * y) % 5,x,z);

	return Aprime;
}

uint8_t *
chi(uint8_t *A)
{
	int x, y, z;
	static uint8_t Aprime[1600];

	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			for (z = 0; z < 64; z++)
				Aprime(x,y,z) = A(x,y,z) ^ ((A((x + 1) % 5,y,z) ^ 1) & A((x + 2) % 5,y,z));

	return Aprime;
}

uint8_t *
iota(uint8_t *A, int ir)
{
	int z;

	for (z = 0; z < 64; z++)
		A(0,0,z) ^= RC[z][ir];

	return A;
}

uint8_t *
Rnd(uint8_t *A, int ir)
{
	return iota(chi(pi(rho(theta(A)))), ir);
}

uint8_t keccak_mask[8] = {1,2,4,8,0x10,0x20,0x40,0x80};

void
Keccak(uint8_t *S)
{
	int ir, k, x, y, z;
	static uint8_t a[1600], *A = a;

	// convert S to A

	memset(A, 0, 1600);

	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			for (z = 0; z < 64; z++) {
				k = 64 * (5 * y + x) + z;
				if (S[k / 8] & keccak_mask[k % 8])
					A(x,y,z) = 1;
			}

	for (ir = 0; ir < 24; ir++)
		A = Rnd(A, ir);

	// convert A to S

	memset(S, 0, 200);

	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			for (z = 0; z < 64; z++)
				if (A(x,y,z)) {
					k = 64 * (5 * y + x) + z;
					S[k / 8] |= keccak_mask[k % 8];
				}
}

uint8_t *
sponge(uint8_t *N, int len)
{
	int i, j, k, n;
	static uint8_t S[200]; // 1600 bits

	memset(S, 0, 200);

	n = len / RATE; // number of full blocks

	for (i = 0; i < n; i++) {
		for (j = 0; j < RATE; j++)
			S[j] ^= N[RATE * i + j];
		Keccak(S);
	}

	// pad last block

	k = len % RATE;

	for (i = 0; i < k; i++)
		S[i] ^= N[RATE * n + i];

	S[k] ^= 0x01;
	S[RATE - 1] ^= 0x80;

	Keccak(S);

	return S;
}

void
keccak256(uint8_t *outbuf, uint8_t *inbuf, int inbuflen)
{
	uint8_t *S = sponge(inbuf, inbuflen);
	memcpy(outbuf, S, 32);
}

void
keccak256_setup(struct mac_state_t *p)
{
	memset(p->S, 0, 200);
	p->index = 0;
}

// reads from buf

void
keccak256_update(struct mac_state_t *p, uint8_t *buf, int len)
{
	int i, j, n;

	// finish pending block

	n = RATE - p->index;

	if (n > len)
		n = len;

	for (i = 0; i < n; i++)
		p->S[p->index + i] ^= buf[i];

	p->index += n;

	if (p->index < RATE)
		return;

	Keccak(p->S);

	// remaining blocks

	buf += n;
	len -= n;

	n = len / RATE; // number of full blocks

	for (i = 0; i < n; i++) {
		for (j = 0; j < RATE; j++)
			p->S[j] ^= buf[RATE * i + j];
		Keccak(p->S);
	}

	// remainder

	p->index = len % RATE;

	for (i = 0; i < p->index; i++)
		p->S[i] ^= buf[RATE * n + i];
}

// writes to buf

void
keccak256_digest(struct mac_state_t *p, uint8_t *buf)
{
	uint8_t S[200];

	memcpy(S, p->S, 200);

	S[p->index] ^= 0x01;
	S[RATE - 1] ^= 0x80;

	Keccak(S);

	memcpy(buf, S, 32);
}

#define STR1 "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
#define STR2 "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
#define STR3 "34367dc248bbd832f4e3e69dfaac2f92638bd0bbd18f2912ba4ef454919cf446"
#define STR4 "a6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e"
#define STR5 "d869f639c7046b4929fc92a4d988a8b22c55fbadb802c0c66ebcd484f1915f39"

void
test_keccak256(void)
{
	int err;
	uint8_t buf[RATE + 1], h[32], hash[32];
	struct mac_state_t mac_state;

	printf("Test keccak ");

	memset(buf, 'a', sizeof buf);

	hextobin(h, 32, STR1);
	keccak256(hash, buf, 0);
	err = memcmp(h, hash, 32);
	if (err) {
		trace();
		return;
	}

	hextobin(h, 32, STR2);
	keccak256(hash, (uint8_t *) "hello", 5);
	err = memcmp(h, hash, 32);
	if (err) {
		trace();
		return;
	}

	hextobin(h, 32, STR3);
	keccak256(hash, buf, RATE - 1);
	err = memcmp(h, hash, 32);
	if (err) {
		trace();
		return;
	}

	hextobin(h, 32, STR4);
	keccak256(hash, buf, RATE);
	err = memcmp(h, hash, 32);
	if (err) {
		trace();
		return;
	}

	hextobin(h, 32, STR5);
	keccak256(hash, buf, RATE + 1);
	err = memcmp(h, hash, 32);
	if (err) {
		trace();
		return;
	}

	keccak256_setup(&mac_state);
	keccak256_update(&mac_state, buf, RATE + 1);
	keccak256_digest(&mac_state, hash);
	err = memcmp(h, hash, 32);
	if (err) {
		trace();
		return;
	}

	printf("ok\n");
}
