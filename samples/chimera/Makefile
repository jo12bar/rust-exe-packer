CFLAGS  := -fPIC
LDFLAGS := -nostartfiles -nodefaultlibs -L. -Wl,-rpath='$$ORIGIN'

all: chimera

chimera: chimera.c libfoo.so libbar.so
	gcc -c chimera.c ${CFLAGS}
	gcc chimera.o -o chimera -lfoo -lbar ${LDFLAGS}

libfoo.so: foo.c
	gcc -c foo.c ${CFLAGS}
	gcc foo.o -shared -o libfoo.so ${LDFLAGS}

libbar.so: bar.c
	gcc -c bar.c ${CFLAGS}
	gcc bar.o -shared -o libbar.so ${LDFLAGS}


clean:
	rm -f chimera *.o *.so
