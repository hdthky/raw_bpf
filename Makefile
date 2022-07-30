PROG := rbpf
HDRS := $(sort $(wildcard include/*.h))

CFLAGS += -I include -static -w

all: $(PROG)

%: %.c $(HDRS)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(PROG)