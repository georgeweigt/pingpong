#include <stdio.h>
#include <stdint.h>

#define A(x, y, z) A[5 * (x) + (y) + 25 * (z)]
#define Aprime(x, y, z) Aprime[5 * (x) + (y) + 25 * (z)]

#define b 1600
#define w 64
#define l 6

int *
theta(int *A)
{
	int x, y, z;
	static int Aprime[25 * w], C[5][w], D[5][w];

	for (x = 0; x < 5; x++)
		for (z = 0; z < w; z++)
			C[x][z] = A(x,0,z) ^ A(x,1,z) ^ A(x,2,z) ^ A(x,3,z) ^ A(x,4,z);

	for (x = 0; x < 5; x++)
		for (z = 0; z < w; z++)
			D[x][z] = C[(x - 1) % 5][z] ^ C[(x + 1) % 5][(z - 1) % w];

	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			for (z = 0; z < w; z++)
				Aprime(x,y,z) = A(x,y,z) ^ D[x][z];

	return Aprime;
}

int *
rho(int *A)
{
	int t, x, xprime, y, yprime, z;
	static int Aprime[25 * w];

	for (z = 0; z < w; z++)
		Aprime(0,0,z) = A(0,0,z);

	x = 1;
	y = 0;

	for (t = 0; t < 24; t++) {
		for (z = 0; z < w; z++)
			Aprime(x,y,z) = A(x,y,(z - (t + 1) * (t + 2) / 2) % w);
		xprime = y;
		yprime = (2 * x + 3 * y) % 5;
		x = xprime;
		y = yprime;
	}

	return Aprime;
}

int *
pi(int *A)
{
	int x, y, z;
	static int Aprime[25 * w];

	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			for (z = 0; z < w; z++)
				Aprime(x,y,z) = A((x + 3 * y) % 5,x,z);

	return Aprime;
}

int *
chi(int *A)
{
	int x, y, z;
	static int Aprime[25 * w];

	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			for (z = 0; z < w; z++)
				Aprime(x,y,z) = A(x,y,z) ^ ((A((x + 1) % 5,y,z) ^ 1) * A((x + 2) % 5,y,z));

	return Aprime;
}

int
rc(int t)
{
	int i, r, R = 128;

	r = t % 255;

	if (r == 0)
		return 1;

	for (i = 0; i < r; i++) {
		R <<= 1;
		if (R & 0x100)
			R ^= 0x171;
	}

	return R & 1;
}

int *
iota(int *A, int ir)
{
	int i, j, x, y, z, RC[w];
	static int Aprime[25 * w];

	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			for (z = 0; z < w; z++)
				Aprime(x,y,z) = A(x,y,z);
	for (i = 0; i < w; i++)
		RC[i] = 0;

	for (j = 0; j <= l; j++)
		RC[(1 << j) - 1] = rc(j + 7 * ir);

	for (z = 0; z < w; z++)
		Aprime(0,0,z) = Aprime(0,0,z) ^ RC[z];

	return Aprime;
}

int *
Rnd(int *A, int ir)
{
	return iota(chi(pi(rho(theta(A)))), ir);
}

uint8_t *
Keccak_p(uint8_t *S, int nr)
{
	int i, ir, k, x, y, z, a[25 * w], *A = a;
	static uint8_t Sprime[b / 8];

	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			for (z = 0; z < w; z++) {
				k = w * (5 * y + x) + z;
				if (S[k / 8] & (1 << (k % 8)))
					A(x,y,z) = 1;
				else
					A(x,y,z) = 0;
			}

	for (ir = 12 + 2 * l - nr; ir <= 12 + 2 * l - 1; ir++)
		A = Rnd(A, ir);

	for (i = 0; i < b / 8; i++)
		Sprime[i] = 0;

	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			for (z = 0; z < w; z++)
				if (A(x,y,z)) {
					k = w * (5 * y + x) + z;
					Sprime[k / 8] |= 1 << (k % 8);
				}

	return Sprime;
}

uint8_t *
Keccak_f(uint8_t *S)
{
	return Keccak_p(S, 12 + 2 * l);
}

int
main()
{
}
