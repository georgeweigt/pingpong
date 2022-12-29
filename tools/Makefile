.PHONY: update

make-prototypes: make-prototypes.c
	gcc -O0 -o make-prototypes make-prototypes.c

update:
	cat ../src/defs.h ../src/prototypes.h ../src/*.c > ../pingpong.c
