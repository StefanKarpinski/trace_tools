USR = $(HOME)/usr
PROGS = bin/parse bin/split bin/trace

default: $(PROGS)

OPTS = -O3
INCLUDES = -Ihdr \
	-I$(USR)/include \
	-I$(USR)/include/glib-2.0 \
	-I$(USR)/include/glib-2.0/glib \
	-I$(USR)/lib/glib-2.0/include
LIBSDIR = -L$(USR)/lib
LIBS = -lglib-2.0 -lpcap

bin/%: src/%.c
	gcc $(OPTS) $(INCLUDES) $(LIBSDIR) $< -o $@ $(LIBS)

clean:
	rm -f $(PROGS)

.PHONY: default clean
