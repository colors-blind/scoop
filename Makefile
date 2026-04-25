#   Building Open Source Network Security Tools
#   Scoop Makefile - Packet Sniffing Technique sample code
#
#   Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
#   All rights reserved.

srcdir		= .

CC		= gcc -g
CFLAGS		= -O2 -D_BSD_SOURCE -Wall
#LDFLAGS	= -L/path/to/libpcap/library/if/needed
OBJECTS         = scoop.o
#INCS		= -I/path/to/libpcap/headers/if/needed
LIBS		= -lpcap

.c.o:
	$(CC) -c $(CFLAGS) $(INCS) $<

all: scoop

scoop: $(OBJECTS)
	$(CC) $(CFLAGS) $(INCS) -o $@ $(OBJECTS) $(LDFLAGS) $(LIBS)

clean:
	rm -f *.o *~ *core* scoop

# EOF
