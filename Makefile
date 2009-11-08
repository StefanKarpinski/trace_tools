USR = /opt/local
PROGS = \
	bin/enumerate \
	bin/histogram \
	bin/parse \
	bin/quantize \
	bin/sortpkts \
	bin/splice \
	bin/stats \
	bin/unpack

default: $(PROGS)

OPTS = -O3
INCLUDES = -Ihdr \
	-I$(USR)/include \
	-I$(USR)/include/glib-2.0 \
	-I$(USR)/include/glib-2.0/glib \
	-I$(USR)/lib/glib-2.0/include
LIBSDIR = -L$(USR)/lib
LIBS = -lglib-2.0 -lpcap -lm

src/flow_desc.c: \
	types/flow_desc.rb \
	types/ip_protocols.csv \
	types/icmp_types.csv   \
	types/port_numbers.csv \
	types/common_ports.csv
	ruby $^ > $@

src/%.o: src/%.c src/common.h src/flow_desc.h
	gcc $(OPTS) $(INCLUDES) -c $< -o $@

bin/%: src/%.o src/common.o src/flow_desc.o
	gcc $(OPTS) $(INCLUDES) $^ -o $@ $(LIBSDIR) $(LIBS)

clean:
	rm -f $(PROGS) src/*.o src/flow_desc.c

.PRECIOUS: src/%.o

.PHONY: default clean
