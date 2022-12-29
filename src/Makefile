.PHONY: clean

a.out: prototypes.h *.h *.c
	gcc -Wall -O0 *.c

prototypes.h: *.c
	make -s -C ../tools make-prototypes
	../tools/make-prototypes . > prototypes.h

clean:
	rm -f a.out
