.PHONY: default

default:
	cat ../src/defs.h ../src/prototypes.h ../src/*.c > ../pingpong.c

make-prototypes: make-prototypes.c
	gcc -O0 -o make-prototypes make-prototypes.c
