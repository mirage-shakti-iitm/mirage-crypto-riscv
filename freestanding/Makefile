PKG_CONFIG_PATH := $(shell opam config var prefix)/riscv-sysroot/lib/pkgconfig
OCAML_BOOT_RISCV_PATH := $(shell opam config var prefix)/riscv-sysroot/include/ocaml-boot-riscv
OCAML_FREESTANDING_RISCV_PATH := $(shell opam config var prefix)/riscv-sysroot/include/ocaml-freestanding-riscv
OCAML_RISCV_PATH := $(shell opam config var prefix)/riscv-sysroot/lib/ocaml

EXISTS := $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) pkg-config --exists ocaml-freestanding-riscv; echo $$?)

.PHONY: all clean display
all: libmirage_crypto_freestanding_stubs.a

ifeq ($(EXISTS), 1)
libmirage_crypto_freestanding_stubs.a:
	touch $@
else
CC = clang
AR = riscv64-unknown-elf-gcc-ar
FREESTANDING_CFLAGS := $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) pkg-config --cflags ocaml-freestanding-riscv) --gcc-toolchain=${RISCV} -march=rv64gc
MIRAGE_CRYPTO_OPT_CFLAGS := $(shell sed 's/^(\(.*\))$$/\1/' ../src/cflags_optimized.sexp | tr -d '"')
COMPARTMENT_FLAGS=-mllvm -enable-compartment-pass -mllvm -default-compartment-id -mllvm 20 -ffunction-sections
# poly1305-donna.c, chacha.c, chacha_generic.c, hash_stubs.c, des_generic.c, des_generic.h, aes_aesni.c, misc_sse.c, ghash_pclmul.c
SHAKTI_MS_FLAGS=-mllvm -enable-shakti-ms -mllvm -ignore-files-shakti-ms -mllvm aes_aesni.c,chacha.c,ghash_ctmul.c,hash_stubs.c,chacha_generic.c,detect_cpu_features.c,poly1305-donna-64.h,des_generic.c,ghash_pclmul.c,misc_sse.c,poly1305-donna.c,entropy_cpu_stubs.c -fno-inline-functions -DFREESTANDING_CRYPTO
CFLAGS := -I../src/native $(MIRAGE_CRYPTO_OPT_CFLAGS) $(FREESTANDING_CFLAGS) $(SHAKTI_MS_FLAGS) -I$(OCAML_RISCV_PATH) -I$(OCAML_BOOT_RISCV_PATH)  -I$(OCAML_FREESTANDING_RISCV_PATH) $(COMPARTMENT_FLAGS)
MIRAGE_CRYPTO_CFLAGS := $(shell sed 's/^(\(.*\))$$/\1/' ../src/cflags.sexp | tr -d '"')
UNOPT_CFLAGS := -I../src/native $(MIRAGE_CRYPTO_CFLAGS) $(FREESTANDING_CFLAGS) -I$(OCAML_RISCV_PATH) -I$(OCAML_BOOT_RISCV_PATH) $(SHAKTI_MS_FLAGS) -I$(OCAML_FREESTANDING_RISCV_PATH) $(COMPARTMENT_FLAGS)
# -I$(OCAML_FREESTANDING_RISCV_PATH)

chacha_generic.o: chacha_generic.c
	$(CC) $(UNOPT_CFLAGS) -c -o chacha_generic.o chacha_generic.c

UNOPT_OBJS=chacha_generic.o

OBJS=detect_cpu_features.o misc.o misc_sse.o hash_stubs.o md5.o sha1.o \
  sha256.o sha512.o aes_generic.o aes_aesni.o des_generic.o chacha.o \
  poly1305-donna.o ghash_pclmul.o ghash_generic.o ghash_ctmul.o \
  entropy_cpu_stubs.o

# display:
# 	echo $(CFLAGS)

libmirage_crypto_freestanding_stubs.a: $(OBJS) $(UNOPT_OBJS)
	$(AR) r $@ $^
endif

clean:
	$(RM) $(OBJS) libmirage_crypto_freestanding_stubs.a


