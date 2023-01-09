.PHONY: clean

pingpong: pingpong.c
	gcc -Wall -O0 -o pingpong pingpong.c

pingpong.c: src/defs.h src/prototypes.h src/*.c
	cat src/defs.h src/prototypes.h src/*.c > pingpong.c

clean:
	rm -f pingpong pingpong.c
