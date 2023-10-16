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
PLUGIN_PREFIX := /usr/lib/openvpn/plugins
BUILDDIR := build

GOLDFLAGS := -ldflags '-extldflags "-static"'
GOFLAGS := -buildmode=pie -a $(GOLDFLAGS)

LIBRARIES := $(BUILDDIR)/libokta-openvpn.so $(BUILDDIR)/defer_simple.so $(BUILDDIR)/openvpn-plugin-okta.so

all: script libs

$(BUILDDIR):
	mkdir $(BUILDDIR)

script: cmd/okta-openvpn/main.go | $(BUILDDIR)
	CGO_ENABLED=0 go build $(GOFLAGS) -o $(BUILDDIR)/okta_openvpn cmd/okta-openvpn/main.go

$(BUILDDIR)/defer_simple.so: $(BUILDDIR)/defer_simple.o openvpn-plugin.h
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,-soname,defer_simple.so -o $(BUILDDIR)/defer_simple.so $(BUILDDIR)/defer_simple.o

$(BUILDDIR)/openvpn-plugin-okta.so: $(BUILDDIR)/libokta-openvpn.so $(BUILDDIR)/defer_okta_openvpn.o openvpn-plugin.h
	$(CC)  $(LDFLAGS) -Wl,-soname,openvpn-plugin-okta.so -o $(BUILDDIR)/openvpn-plugin-okta.so $(BUILDDIR)/defer_okta_openvpn.o $(LIBS)

$(BUILDDIR)/libokta-openvpn.so: lib/libokta-openvpn.go | $(BUILDDIR)
	go build -buildmode=c-shared -o $(BUILDDIR)/libokta-openvpn.so lib/libokta-openvpn.go

$(BUILDDIR)/%.o: %.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -c $< -o $@ $(LIBS)

libs: $(LIBRARIES)

test: $(BUILDDIR)/cover.out

$(BUILDDIR)/cover.out: | $(BUILDDIR)
	# Ensure tests wont fail because of crappy permissions
	chmod -R g-w,o-w testing/fixtures
	go test ./pkg/... -v -cover -coverprofile=$(BUILDDIR)/cover.out -covermode=atomic -coverpkg=./pkg/...

$(BUILDDIR)/coverage.html: $(BUILDDIR)/cover.out
	go tool cover -html=$(BUILDDIR)/cover.out -o $(BUILDDIR)/coverage.html

$(BUILDDIR)/cover-badge.out: $(BUILDDIR)/cover.out
	go tool cover -func=$(BUILDDIR)/cover.out -o=$(BUILDDIR)/cover-badge.out

badge: $(BUILDDIR)/cover-badge.out
	if [ ! -f /tmp/gobadge ]; then \
		curl -sf https://gobinaries.com/github.com/AlexBeauchemin/gobadge@v0.3.0 | PREFIX=/tmp sh; \
	fi
	/tmp/gobadge -filename=$(BUILDDIR)/cover-badge.out

lint:
	golangci-lint run
	cppcheck --enable=all *.c

install: all
	mkdir -p $(DESTDIR)$(PLUGIN_PREFIX)/
	mkdir -p $(DESTDIR)/etc/openvpn/
	$(INSTALL) -m644 $(BUILDDIR)/defer_simple.so $(DESTDIR)$(PLUGIN_PREFIX)/
	$(INSTALL) -m755 $(BUILDDIR)/okta_openvpn $(DESTDIR)$(PLUGIN_PREFIX)/
	$(INSTALL) -m644 $(BUILDDIR)/libokta-openvpn.so $(DESTDIR)$(PLUGIN_PREFIX)/
	$(INSTALL) -m644 $(BUILDDIR)/openvpn-plugin-okta.so $(DESTDIR)$(PLUGIN_PREFIX)/
	$(INSTALL) -m644 okta_pinset.cfg $(DESTDIR)/etc/openvpn/okta_pinset.cfg
	$(INSTALL) -m640 okta_openvpn.ini.inc $(DESTDIR)/etc/openvpn/okta_openvpn.ini

clean:
	rm -Rf $(BUILDDIR)
	rm -f cover.out coverage.html cover-badge.out
	rm -f testing/fixtures/validator/valid_control_file
	rm -f testing/fixtures/validator/invalid_control_file
	rm -f testing/fixtures/validator/control_file

.PHONY: clean install lint badge test badge libs
