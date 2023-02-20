.PHONY: clean checkall

CFILES := $(shell ls *.c)

pingpong: defs.h prototypes.h $(CFILES)
	gcc -Wall -O0 -o pingpong -include defs.h -include prototypes.h $(CFILES)

prototypes.h: $(CFILES)
	make -s -C ../tools make-prototypes
	../tools/make-prototypes . > prototypes.h

clean:
	rm -f pingpong prototypes.h

checkall:
	make -s -C ../tools wcheck
	for FILE in *.h *.c; do ../tools/wcheck $$FILE; done
