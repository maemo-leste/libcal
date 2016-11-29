all: libcal.so.1.0.0

libcal.so.1.0.0: cal.c
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -Wl,-soname=libcal.so.1 $^ -o $@ -lpthread

clean:
	$(RM) libcal.so.1.0.0

install:
	install -d "$(DESTDIR)/usr/include/"
	install -d "$(DESTDIR)/usr/lib/pkgconfig/"
	install -m 644 cal.h "$(DESTDIR)/usr/include/"
	install -m 644 libcal.pc "$(DESTDIR)/usr/lib/pkgconfig/"
	install -m 755 libcal.so.1.0.0 "$(DESTDIR)/usr/lib/"
	ln -s libcal.so.1.0.0 "$(DESTDIR)/usr/lib/libcal.so.1"
	ln -s libcal.so.1.0.0 "$(DESTDIR)/usr/lib/libcal.so"
