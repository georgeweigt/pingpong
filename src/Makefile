.PHONY: clean

pingpong: defs.h prototypes.h *.c
	gcc -Wall -O0 -o pingpong -include defs.h -include prototypes.h *.c

prototypes.h: *.c
	make -s -C ../tools make-prototypes
	../tools/make-prototypes . > prototypes.h

clean:
	rm -f a.out
