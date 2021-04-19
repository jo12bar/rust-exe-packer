CFLAGS := -g
LDFLAGS :=

all: what what-static what-static-pie

what: what.c
	gcc what.c ${CFLAGS} -o what ${LDFLAGS}

what-static: what.c
	gcc -static what.c ${CFLAGS} -o what-static ${LDFLAGS}

what-static-pie:
	gcc -static-pie what.c ${CFLAGS} -o what-static-pie ${LDFLAGS}

clean:
	rm -f what what-static what-static-pie *.o *.so
