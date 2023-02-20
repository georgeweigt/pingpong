.PHONY: clean checkall

HFILES := $(shell ls *.h)
CFILES := $(shell ls *.c)

# specify prototypes.h in case it's missing from HFILES

pingpong: prototypes.h $(HFILES) $(CFILES)
	gcc -Wall -O0 -o pingpong -include defs.h -include prototypes.h $(CFILES)

prototypes.h: $(CFILES)
	make -s -C ../tools make-prototypes
	../tools/make-prototypes . > prototypes.h

clean:
	rm -f pingpong prototypes.h

checkall:
	make -s -C ../tools wcheck
	for FILE in $(HFILES); do ../tools/wcheck $$FILE; done
	for FILE in $(CFILES); do ../tools/wcheck $$FILE; done
