CC = gcc
CFLAGS = -I/usr/local/include/rbus -I/usr/local/include/rtmessage -I/usr/local/include/obuspa/core -I/work/usp-pa-vendor-rdk/src/vendor -g -O0 -fprofile-arcs -ftest-coverage
LDFLAGS = -L/usr/local/lib -lrtMessage -lpthread

test_vendor_notify: test_vendor_notify.c
	$(CC) $(CFLAGS) test_vendor_notify.c -o test_vendor_notify $(LDFLAGS)

clean:
	rm -f test_vendor_notify *.gcno *.gcda *.gcov
