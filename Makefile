# Copyright (C) 2023 Gramine contributors
# SPDX-License-Identifier: BSD-3-Clause

ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
else
GRAMINE_LOG_LEVEL = error
endif

.PHONY: all
all: uProbe.manifest app.manifest
ifeq ($(SGX),1)
all: uProbe.manifest.sgx uProbe.sig app.manifest.sgx app.sig
endif

RA_TYPE ?= none
RA_CLIENT_SPID ?=
RA_CLIENT_LINKABLE ?= 0

app.manifest: manifests/app.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dentrypoint=$(realpath $(shell sh -c "command -v python3")) \
		-Dra_type=$(RA_TYPE) \
		-Dra_client_spid=$(RA_CLIENT_SPID) \
		-Dra_client_linkable=$(RA_CLIENT_LINKABLE) \
		$< > $@

uProbe.manifest: manifests/uProbe.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dentrypoint=/app/dist/uprobe \
		-Dra_type=$(RA_TYPE) \
		-Dra_client_spid=$(RA_CLIENT_SPID) \
		-Dra_client_linkable=$(RA_CLIENT_LINKABLE) \
		$< > $@

# Make on Ubuntu <= 20.04 doesn't support "Rules with Grouped Targets" (`&:`),
# see the helloworld example for details on this workaround.
app.manifest.sgx app.sig: app_sgx_sign
	@:

uProbe.manifest.sgx uProbe.sig: uProbe_sgx_sign
	@:

.INTERMEDIATE: uProbe_sgx_sign app_sgx_sign

app_sgx_sign: app.manifest
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

uProbe_sgx_sign: uProbe.manifest
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx
	

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig OUTPUT* *.PID TEST_STDOUT TEST_STDERR

.PHONY: distclean
distclean: clean