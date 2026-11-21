COMPONENT := ../../components/cs_proxy
CXXFLAGS ?= -std=c++17 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined

all: run

vectors.inc: gen_vectors.py ../../spec/vectors/frame-v1.json ../../spec/vectors/proxy-envelope-v1.json
	python3 gen_vectors.py

test_core: test_core.cpp vectors.inc $(COMPONENT)/proxy_core.cpp $(COMPONENT)/proxy_core.h $(COMPONENT)/cs_sha256.cpp $(COMPONENT)/cs_sha256.h
	$(CXX) $(CXXFLAGS) -I$(COMPONENT) -o $@ test_core.cpp $(COMPONENT)/proxy_core.cpp $(COMPONENT)/cs_sha256.cpp

run: test_core
	./test_core

clean:
	rm -f test_core

.PHONY: all run clean
