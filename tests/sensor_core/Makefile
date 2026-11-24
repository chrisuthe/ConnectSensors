COMPONENT := ../../components/cs_sensor
PROXY := ../../components/cs_proxy
CXXFLAGS ?= -std=c++17 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined

all: run

vectors.inc: gen_vectors.py ../../spec/vectors/frame-v1.json ../../spec/vectors/payload-v1.json ../../spec/vectors/pairing-v1.json ../../spec/tools/csframe.py
	python3 gen_vectors.py

SOURCES := $(COMPONENT)/sensor_core.cpp $(COMPONENT)/cs_crypto.cpp $(COMPONENT)/cs_x25519.cpp $(COMPONENT)/cs_sha256.cpp \
           $(COMPONENT)/cs_sha512.cpp $(COMPONENT)/cs_ed25519.cpp $(COMPONENT)/cs_fe25519.cpp
HEADERS := $(COMPONENT)/sensor_core.h $(COMPONENT)/cs_crypto.h $(COMPONENT)/cs_x25519.h $(COMPONENT)/cs_sha256.h \
           $(COMPONENT)/cs_sha512.h $(COMPONENT)/cs_ed25519.h $(COMPONENT)/cs_fe25519.h \
           $(COMPONENT)/cs_ed25519_table.h ref_tweetnacl.h

test_core: test_core.cpp vectors.inc $(SOURCES) $(HEADERS)
	$(CXX) $(CXXFLAGS) -I$(COMPONENT) -o $@ test_core.cpp $(SOURCES)

# Not a gate: prints old against new key generation times (#95).
BENCH_SOURCES := $(COMPONENT)/cs_ed25519.cpp $(COMPONENT)/cs_fe25519.cpp $(COMPONENT)/cs_x25519.cpp \
                 $(COMPONENT)/cs_sha512.cpp $(COMPONENT)/cs_crypto.cpp $(COMPONENT)/cs_sha256.cpp
bench_keygen: bench_keygen.cpp $(BENCH_SOURCES) $(HEADERS)
	$(CXX) -std=c++17 -Os -Wall -Wextra -Werror -I$(COMPONENT) -o $@ bench_keygen.cpp $(BENCH_SOURCES)

# cs_sha256 and cs_clock are copied from cs_proxy rather than shared (see components/cs_sensor/README.md).
shared-copy:
	@for f in cs_sha256.h cs_sha256.cpp cs_clock.h; do \
	  sed 's/cs_proxy/cs_sensor/g' $(PROXY)/$$f | diff -u - <(grep -v '^// Copy of' $(COMPONENT)/$$f) \
	    || { echo "$(COMPONENT)/$$f has drifted from $(PROXY)/$$f"; exit 1; }; \
	done
	@# So are the region tables: ESPHome loads only listed components, so neither can import the other.
	@for t in REGIONS PENDING_REGIONS; do \
	  a=$$(sed -n "/^$$t = {/,/^}/p" $(PROXY)/__init__.py); \
	  b=$$(sed -n "/^$$t = {/,/^}/p" $(COMPONENT)/__init__.py); \
	  [ -n "$$a" ] || { echo "no $$t table in $(PROXY)/__init__.py"; exit 1; }; \
	  diff -u <(echo "$$a") <(echo "$$b") \
	    || { echo "$$t in $(COMPONENT)/__init__.py has drifted from $(PROXY)/__init__.py"; exit 1; }; \
	done

# The comb table is generated; fail if the committed one has drifted from the script.
table-check:
	python3 gen_ed25519_table.py --check

run: test_core bench_keygen shared-copy table-check
	./test_core
	./bench_keygen

clean:
	rm -f test_core bench_keygen vectors.inc

SHELL := /bin/bash
.PHONY: all run clean shared-copy table-check
