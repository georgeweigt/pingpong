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

#undef RATE
#undef A
#undef Aprime
