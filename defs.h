#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>

#define len(p) (p)[-1]

#define Trace printf("file %s, line %d\n", __FILE__, __LINE__);

extern int ec_malloc_count;

struct point {
	uint32_t *x, *y, *z;
};

uint32_t * ec_modinv(uint32_t *c, uint32_t *p);
void ec_projectify(struct point *S);
void ec_affinify(struct point *S, uint32_t *p);
void ec_double(struct point *R, struct point *S, uint32_t *p);
void ec_add_xyz(struct point *R, struct point *S, struct point *T, uint32_t *p);
void ec_full_add(struct point *R, struct point *S, struct point *T, uint32_t *p);
void ec_full_sub(struct point *R, struct point *S, struct point *T, uint32_t *p);
void ec_mult(struct point *R, uint32_t *d, struct point *S, uint32_t *p);
int ec_get_msbit_index(uint32_t *u);
int ec_get_bit(uint32_t *u, int k);
int ec_F(int t);
void ec_twin_mult(struct point *R, uint32_t *d0, struct point *S, uint32_t *d1, struct point *T, uint32_t *p);
void ec_free_xyz(struct point *u);
uint32_t * ec_add(uint32_t *u, uint32_t *v);
uint32_t * ec_sub(uint32_t *u, uint32_t *v);
uint32_t * ec_mul(uint32_t *u, uint32_t *v);
uint32_t * ec_div(uint32_t *u, uint32_t *v);
void ec_mod(uint32_t *u, uint32_t *v);
uint32_t * ec_pow(uint32_t *u, uint32_t *v);
void ec_shr(uint32_t *u);
int ec_cmp(uint32_t *u, uint32_t *v);
int ec_equal(uint32_t *u, uint32_t v);
uint32_t * ec_int(int k);
uint32_t * ec_new(int n);
void ec_free(uint32_t *u);
uint32_t * ec_dup(uint32_t *u);
void ec_norm(uint32_t *u);
uint32_t * ec_hexstr_to_bignum(char *s);
void ec_test();
void ec_test_full_add();
void ec_test_full_sub();
void ec_test_double();
void ec_test_mult();
void ec_test_twin_mult();
