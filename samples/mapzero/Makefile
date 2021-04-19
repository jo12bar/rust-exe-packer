CFLAGS := -g -static
LDFLAGS :=

all: mapzero

mapzero: mapzero.c
	gcc mapzero.c ${CFLAGS} -o mapzero ${LDFLAGS}

clean:
	rm -f mapzero *.o *.so
