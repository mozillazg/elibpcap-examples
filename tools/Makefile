.ONESHELL:
# .SHELLFLAGS = -e
SHELL = /bin/sh

GIT = $(shell which git || /bin/false)
OUTPUT = ../output

LIBPCAP = ../libpcap
LIBPCAP_SRC =  $(abspath $(LIBPCAP))
LIBPCAP_DIST_DIR ?= $(abspath $(OUTPUT)/libpcap)
LIBPCAP_HEADER_DIR = $(abspath $(LIBPCAP_DIST_DIR)/include)
LIBPCAP_OBJ_DIR = $(abspath $(LIBPCAP_DIST_DIR)/lib)
LIBPCAP_OBJ = $(abspath $(LIBPCAP_OBJ_DIR)/libpcap.a)

CGO_CFLAGS_STATIC = "-I$(LIBPCAP_HEADER_DIR)"
CGO_LDFLAGS_STATIC = "-L$(LIBPCAP_OBJ_DIR) -lpcap $(LIBPCAP_OBJ)"
CGO_ENABLED ?= 1
GOARCH ?= $(shell go env GOARCH)
GOOS ?= $(shell go env GOOS)
LDFLAGS := -linkmode "external" -extldflags "-static"

CARCH ?= $(shell uname -m)
LIBPCAP_HOST = $(CARCH)-unknown-linux-gnu
GCC ?= gcc

.PHONY: libpcap
libpcap: $(LIBPCAP_OBJ)

$(LIBPCAP_OBJ): $(LIBPCAP_SRC)/pcap.h $(wildcard $(LIBPCAP_SRC)/*.[ch]) | $(LIBPCAP_DIST_DIR)
	cd $(LIBPCAP_SRC) && \
	  sh autogen.sh && \
	  CC=$(GCC) ./configure --disable-shared --disable-usb --disable-netmap --disable-bluetooth --disable-dbus --without-libnl \
	  	--disable-rdma --host=$(LIBPCAP_HOST) && \
	  $(MAKE) && \
	  $(MAKE) install prefix=$(LIBPCAP_DIST_DIR)

$(LIBPCAP_SRC)/pcap.h:
ifeq ($(wildcard $@), )
	echo "INFO: updating submodule 'libpcap'"
	$(GIT) submodule update --init --recursive
endif

$(LIBPCAP_DIST_DIR): $(LIBPCAP_SRC)

$(OUTPUT):
	mkdir -p $(OUTPUT)


.PHONY: build
build: libpcap
	CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
	CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
	GOARCH=$(GOARCH) \
	CC=$(GCC) \
	CGO_ENABLED=1 go build -o main -tags static -ldflags "$(LDFLAGS)"


.PHONY: build-dynamic-link
build-dynamic-link:
	CGO_ENABLED=1 go build -o main -tags dynamic

.PHONY: generate
generate: build-bpf

.PHONY: build-bpf
build-bpf:
	go generate ./...

.PHONY: clean
clean:
	$(MAKE) -C $(LIBPCAP_SRC) clean
	rm -rf $(OUTPUT)


filter ?= "icmp"

.PHONY: run
run:
	sudo ./main "$(filter)"
