SHELL := bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c

MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

INSTALL := install
CC := gcc
CFLAGS := -fPIC -I.
LDFLAGS := -shared -fPIC
LIBS := -Lbuild -lokta-openvpn

DESTDIR := /
LIB_PREFIX := /usr/lib
PLUGIN_DIR := openvpn/plugins
BUILDDIR := build

GOLDFLAGS := -ldflags '-extldflags "-static"'
GOFLAGS := -buildmode=pie -a $(GOLDFLAGS)

LIBRARIES := $(BUILDDIR)/libokta-openvpn.so $(BUILDDIR)/defer_simple.so $(BUILDDIR)/openvpn-plugin-okta.so

all: $(BUILDDIR)/okta_openvpn libs

$(BUILDDIR):
	mkdir $(BUILDDIR)


$(BUILDDIR)/%.o: %.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -c $< -o $@


# Build the plugin as a standalone binary
$(BUILDDIR)/okta_openvpn: cmd/okta-openvpn/main.go | $(BUILDDIR)
	CGO_ENABLED=0 go build $(GOFLAGS) -o $(BUILDDIR)/okta_openvpn cmd/okta-openvpn/main.go


# Build the defer_simple plugin (used as a wrapper for the standalone binary)
$(BUILDDIR)/defer_simple.so: $(BUILDDIR)/defer_simple.o openvpn-plugin.h
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,-soname,defer_simple.so -o $(BUILDDIR)/defer_simple.so $(BUILDDIR)/defer_simple.o

# Build the openvpn-plugin-okta plugin (linked against the Go c-shared lib)
$(BUILDDIR)/openvpn-plugin-okta.so: $(BUILDDIR)/libokta-openvpn.so $(BUILDDIR)/defer_okta_openvpn.o openvpn-plugin.h
	$(CC)  $(LDFLAGS) -Wl,-soname,openvpn-plugin-okta.so -o $(BUILDDIR)/openvpn-plugin-okta.so $(BUILDDIR)/defer_okta_openvpn.o

# Build the okta-openvpn shared lib (Golang c-shared)
$(BUILDDIR)/libokta-openvpn.so: lib/libokta-openvpn.go | $(BUILDDIR)
	go build -buildmode=c-shared -o $(BUILDDIR)/libokta-openvpn.so lib/libokta-openvpn.go

$(BUILDDIR)/test_direct_load: $(BUILDDIR)/libokta-openvpn.so
	gcc $(CFLAGS) -ggdb -o build/test_direct_load testing/test_direct_load.c $(LIBS)

# Build all shared libraries
libs: $(LIBRARIES)

test: $(BUILDDIR)/cover.out

test-c: $(BUILDDIR)/test_direct_load $(BUILDDIR)/test_defer_plugin
	$(BUILDDIR)/test_direct_load

coverage: $(BUILDDIR)/coverage.html

badge: $(BUILDDIR)/cover-badge.out
	if [ ! -f /tmp/gobadge ]; then \
		curl -sf https://gobinaries.com/github.com/AlexBeauchemin/gobadge@v0.3.0 | PREFIX=/tmp sh; \
	fi
	/tmp/gobadge -filename=$(BUILDDIR)/cover-badge.out

# Run tests that generates the cover.out
$(BUILDDIR)/cover.out: | $(BUILDDIR)
	# Ensure tests wont fail because of crappy permissions
	chmod -R g-w,o-w testing/fixtures
	go test ./pkg/... -v -cover -coverprofile=$(BUILDDIR)/cover.out -covermode=atomic -coverpkg=./pkg/...

# Creates the coverage.html
$(BUILDDIR)/coverage.html: $(BUILDDIR)/cover.out
	go tool cover -html=$(BUILDDIR)/cover.out -o $(BUILDDIR)/coverage.html

# Creates the cover-badgeout (needed for README badge link creation)
$(BUILDDIR)/cover-badge.out: $(BUILDDIR)/cover.out
	go tool cover -func=$(BUILDDIR)/cover.out -o=$(BUILDDIR)/cover-badge.out


lint:
	golangci-lint run
	cppcheck --enable=all *.c

install: all
	mkdir -p $(DESTDIR)/$(LIB_PREFIX)/$(PLUGIN_DIR)
	mkdir -p $(DESTDIR)/etc/openvpn/
	mkdir -p $(DESTDIR)/usr/include
	$(INSTALL) -m755 $(BUILDDIR)/okta_openvpn $(DESTDIR)/$(LIB_PREFIX)/$(PLUGIN_DIR)/
	$(INSTALL) -m644 $(BUILDDIR)/defer_simple.so $(DESTDIR)/$(LIB_PREFIX)/$(PLUGIN_DIR)/
	$(INSTALL) -m644 $(BUILDDIR)/libokta-openvpn.so $(DESTDIR)/$(LIB_PREFIX)/
	$(INSTALL) -m644 $(BUILDDIR)/libokta-openvpn.h $(DESTDIR)/usr/include/
	$(INSTALL) -m644 $(BUILDDIR)/openvpn-plugin-okta.so $(DESTDIR)/$(LIB_PREFIX)/$(PLUGIN_DIR)/
	if [ ! -f $(DESTDIR)/etc/openvpn/okta_pinset.cfg ]; then \
		$(INSTALL) -m644 okta_pinset.cfg $(DESTDIR)/etc/openvpn/okta_pinset.cfg; \
	fi
	if [ ! -f $(DESTDIR)/etc/openvpn/okta_openvpn.ini ]; then \
		$(INSTALL) -m640 okta_openvpn.ini.inc $(DESTDIR)/etc/openvpn/okta_openvpn.ini; \
	fi

clean:
	rm -Rf $(BUILDDIR)
	rm -f testing/fixtures/validator/valid_control_file
	rm -f testing/fixtures/validator/invalid_control_file
	rm -f testing/fixtures/validator/control_file

.PHONY: clean install lint badge coverage test libs
