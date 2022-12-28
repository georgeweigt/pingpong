#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define A(x,y,z) A[320 * (x) + 64 * (y) + (z)]
#define Aprime(x,y,z) Aprime[320 * (x) + 64 * (y) + (z)]

int foo;

void
print(uint8_t *A)
{
	int x, y, z;
	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			for (z = 0; z < 64; z++)
				printf("%d", A(x,y,z));
	printf("\n");
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

	for (t = 0; t <= 23; t++) {
		for (z = 0; z < 64; z++)
			Aprime(x,y,z) = A(x,y,(5 * 64 + z - (t + 1) * (t + 2) / 2) % 64);
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

uint8_t RC[64][24];

uint8_t
rc(int t)
{
	int i, R;

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

#if 0
uint8_t mask[8] = {0x80,0x40,0x20,0x10,8,4,2,1};
#else
uint8_t mask[8] = {1,2,4,8,0x10,0x20,0x40,0x80}; // S[0] is least significant bit
#endif

void
Keccak(uint8_t *S)
{
	int i, ir, k, x, y, z;
	uint8_t a[1600], *A = a;

	// convert S to A

	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			for (z = 0; z < 64; z++) {
				k = 64 * (5 * y + x) + z;
				if (S[199 - k / 8] & mask[k % 8]) // big endian 
					A(x,y,z) = 1;
				else
					A(x,y,z) = 0;
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
					S[199 - k / 8] |= mask[k % 8]; // big endian
				}
}

uint8_t *
sponge(uint8_t *N, int len) // len is length in bytes
{
	int i, j, k, n;
	static uint8_t S[200]; // 1600 bits

	for (i = 0; i < 200; i++)
		S[i] = 0;
#if 0
	n = len / 168; // number of full blocks 168 == 200 - 32

	for (i = 0; i < n - 1; i++) {
		for (j = 0; j < 168; j++)
			S[j] ^= N[168 * i + j];
		Keccak(S);
	}

	// pad last block

	k = len % 168;

	for (i = 0; i < k; i++)
		S[i] ^= N[168 * n + i];
#endif
	switch (foo) {
	case 0:
		S[0] ^= 0x01;
		S[167] ^= 0x80;
		break;
	case 1:
		S[0] ^= 0x80;
		S[167] ^= 0x01;
		break;
	case 2:
		S[32] ^= 0x01;
		S[199] ^= 0x80;
		break;
	case 3:
		S[32] ^= 0x80;
		S[199] ^= 0x01;
		break;
	case 4:
		S[0] ^= 0x01;
		S[31] ^= 0x80;
		break;
	case 5:
		S[0] ^= 0x80;
		S[31] ^= 0x01;
		break;
	case 6:
		S[168] ^= 0x01;
		S[199] ^= 0x80;
		break;
	case 7:
		S[168] ^= 0x80;
		S[199] ^= 0x01;
		break;
	}

	Keccak(S);

	return S;
}

int
main()
{
	int i, j;
	uint8_t *S;

	for (i = 0; i < 24; i++)
		for (j = 0; j <= 6; j++)
			RC[(1 << j) - 1][i] = rc(j + 7 * i);

	for (foo = 0; foo < 8; foo++) {

		S = sponge((uint8_t *) "hello", 0);

		printf("%02x %02x\n", S[0], S[199]);
	}
}
