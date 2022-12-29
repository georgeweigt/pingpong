.PHONY: clean

a.out: pingpong.c
	gcc -Wall -O0 pingpong.c

clean:
	rm -f a.out
