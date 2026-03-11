CC = gcc
CFLAGS = -I/usr/local/include/rbus -I/usr/local/include/rtmessage -g -O2
LDFLAGS = -L/usr/local/lib -lrbus -lrtMessage -lpthread

stress_provider: stress_provider.c
	$(CC) $(CFLAGS) stress_provider.c -o stress_provider $(LDFLAGS)

clean:
	rm -f stress_provider
