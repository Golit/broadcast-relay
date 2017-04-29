UTILITY := broadcast-relay

CFLAGS := -Wall -std=c11
CPPFLAGS := -D_DEFAULT_SOURCE
LDFLAGS := -s
LDLIBS := -Wl,-Bstatic -lpcap -Wl,-Bdynamic -lnl-genl-3 -lnl-3 -ldbus-1
# LDLIBS := -Wl,-Bstatic $(shell pcap-config --libs --static) -Wl,-Bdynamic

SOURCES := broadcast-relay.c
OBJECTS := $(SOURCES:.c=.o)

.PHONY: clean

$(UTILITY): $(OBJECTS)

clean:
	rm -f $(UTILITY) $(OBJECTS)
