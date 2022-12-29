a.out: prototypes.h *.h *.c
	gcc -Wall main.c ec.c ecdsa.c keccak.c

prototypes.h: *.c
	make -s -C ../tools make-prototypes
	../tools/make-prototypes . > prototypes.h
