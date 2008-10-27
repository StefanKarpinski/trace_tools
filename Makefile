USR = $(HOME)/usr
PROGS = bin/process

default: $(PROGS)

OPTS = -O3
INCLUDES = -Ihdr \
	-I$(USR)/include \
	-I$(USR)/include/glib-2.0 \
	-I$(USR)/include/glib-2.0/glib \
	-I$(USR)/lib/glib-2.0/include
LIBSDIR = -L$(USR)/lib
LIBS = -lglib-2.0 -lpcap -lm

src/%.o: src/%.c src/common.h
	gcc $(OPTS) $(INCLUDES) -c $< -o $@

bin/%: src/%.o src/common.o
	gcc $(OPTS) $(INCLUDES) $^ -o $@ $(LIBSDIR) $(LIBS)

clean:
	rm -f $(PROGS) src/*.o

.PRECIOUS: src/%.o

.PHONY: default clean
