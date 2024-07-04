CC ?= /usr/bin/cc
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wpointer-arith -O3 -fomit-frame-pointer -I/usr/include/openssl
NISTFLAGS += -Wno-unused-result -O3 -fomit-frame-pointer
LDFLAGS += -L/usr/lib -lcrypto
RM = /bin/rm

SOURCES = kyber-pake.c kem.c indcpa.c polyvec.c poly.c ntt.c cbd.c reduce.c verify.c 
SOURCESKECCAK = $(SOURCES) fips202.c symmetric-shake.c
SOURCESNINETIES = $(SOURCES) sha256.c sha512.c aes256ctr.c symmetric-aes.c
HEADERS = params.h kyber-pake.h kem.h indcpa.h polyvec.h poly.h ntt.h cbd.h reduce.c verify.h symmetric.h
HEADERSKECCAK = $(HEADERS) fips202.h
HEADERSNINETIES = $(HEADERS) aes256ctr.h sha2.h

.PHONY: all speed shared clean

all: \
	kyber_pake\
	speed_kyberpake512 \
	speed_kyberpake768 \
	speed_kyberpake1024 \

kyber_pake: \
  kyberpake512 \
  kyberpake768 \
  kyberpake1024 \

kyber_pake_speed: \
  speed_kyberpake512 \
  speed_kyberpake768 \
  speed_kyberpake1024 \

speed_kyberpake512: \
  speed_kyberpake512 \

speed_kyberpake768: \
  speed_kyberpake768 \

speed_kyberpake1024: \
  speed_kyberpake1024 \


kyberpake512: $(SOURCESKECCAK) $(HEADERSKECCAK) test_kyber.c randombytes.c
	$(CC) $(CFLAGS) $(LDFLAGS) -DKYBER_K=2 $(SOURCESKECCAK) randombytes.c test_kyber.c -o kyberpake512 -lcrypto

kyberpake768: $(SOURCESKECCAK) $(HEADERSKECCAK) test_kyber.c randombytes.c
	$(CC) $(CFLAGS) $(LDFLAGS) -DKYBER_K=3 $(SOURCESKECCAK) randombytes.c test_kyber.c -o kyberpake768 -lcrypto

kyberpake1024: $(SOURCESKECCAK) $(HEADERSKECCAK) test_kyber.c randombytes.c
	$(CC) $(CFLAGS) $(LDFLAGS) -DKYBER_K=4 $(SOURCESKECCAK) randombytes.c test_kyber.c -o kyberpake1024 -lcrypto

speed_kyberpake512: $(SOURCESKECCAK) $(HEADERSKECCAK) cpucycles.h cpucycles.c speed_print.h speed_print.c test_speed.c randombytes.c
	$(CC) $(CFLAGS) $(LDFLAGS) -DKYBER_K=2 $(SOURCESKECCAK) randombytes.c cpucycles.c speed_print.c test_speed.c -o speed_kyberpake512 -lcrypto

speed_kyberpake768: $(SOURCESKECCAK) $(HEADERSKECCAK) cpucycles.h cpucycles.c speed_print.h speed_print.c test_speed.c randombytes.c
	$(CC) $(CFLAGS) $(LDFLAGS) -DKYBER_K=3 $(SOURCESKECCAK) randombytes.c cpucycles.c speed_print.c test_speed.c -o speed_kyberpake768 -lcrypto

speed_kyberpake1024: $(SOURCESKECCAK) $(HEADERSKECCAK) cpucycles.h cpucycles.c speed_print.h speed_print.c test_speed.c randombytes.c
	$(CC) $(CFLAGS) $(LDFLAGS) -DKYBER_K=4 $(SOURCESKECCAK) randombytes.c cpucycles.c speed_print.c test_speed.c -o speed_kyberpake1024 -lcrypto

clean:
	-$(RM) -rf *.gcno *.gcda *.lcov *.o *.so
	-$(RM) -rf kyberpake512
	-$(RM) -rf kyberpake768
	-$(RM) -rf kyberpake1024
	-$(RM) -rf speed_kyberpake512
	-$(RM) -rf speed_kyberpake768
	-$(RM) -rf speed_kyberpake1024

