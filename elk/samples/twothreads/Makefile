CFLAGS := -pthread
LDFLAGS :=

all: twothreads

twothreads: twothreads.c
	gcc -g twothreads.c ${CFLAGS} -o twothreads ${LDFLAGS}

clean:
	rm -f twothreads *.o *.so
