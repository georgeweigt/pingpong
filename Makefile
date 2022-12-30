.PHONY: clean

a.out: pingpong.c
	gcc -Wall -O0 pingpong.c

pingpong.c: src/defs.h src/prototypes.h src/*.c
	cat src/defs.h src/prototypes.h src/*.c > pingpong.c

clean:
	rm -f pingpong.c a.out
