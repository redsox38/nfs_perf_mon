CC=gcc
CCFLAGS=-O
EXEC=find_io_killer
LDFLAGS=
LIBS=-ljson-c -lpcap

SOURCES=diagnose.c
OBJS=$(SOURCES:.c=.o)

$(EXEC): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $(EXEC) $(LIBS)

%.o: %.c
	$(CC) -c $(CCFLAGS) $< -o $@

clean:
	rm -f $(EXEC) $(OBJS)
