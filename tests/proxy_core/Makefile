COMPONENT := ../../components/cs_proxy
CXXFLAGS ?= -std=c++17 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined

all: run

vectors.inc: gen_vectors.py ../../spec/vectors/frame-v1.json ../../spec/vectors/proxy-envelope-v1.json ../../spec/tools/csframe.py
	python3 gen_vectors.py

SOURCES := $(COMPONENT)/proxy_core.cpp $(COMPONENT)/proxy_engine.cpp $(COMPONENT)/cs_sha256.cpp
HEADERS := $(COMPONENT)/proxy_core.h $(COMPONENT)/proxy_engine.h $(COMPONENT)/cs_sha256.h

test_core: test_core.cpp vectors.inc $(SOURCES) $(HEADERS)
	$(CXX) $(CXXFLAGS) -I$(COMPONENT) -o $@ test_core.cpp $(SOURCES)

run: test_core
	./test_core

clean:
	rm -f test_core

.PHONY: all run clean
