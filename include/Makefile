-include ../config.mk

xbps.h: xbps.h.in
	sed -e "s|@@VERSION@@|${VERSION}|g" xbps.h.in > xbps.h

.PHONY: all
all: xbps.h

.PHONY: install
install:
	install -d $(DESTDIR)$(INCLUDEDIR)/xbps
	install -m 644 xbps.h $(DESTDIR)$(INCLUDEDIR)
	for f in array bool data dictionary number object string; do \
		install -m 644 xbps/xbps_$${f}.h $(DESTDIR)$(INCLUDEDIR)/xbps; \
	done

.PHONY: uninstall
uninstall:
	-rm -f $(DESTDIR)$(INCLUDEDIR)/$(INCS)

.PHONY: clean
clean:
	-rm -f xbps.h
