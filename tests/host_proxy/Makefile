COMPONENT := ../../components/cs_proxy
CXXFLAGS ?= -std=c++17 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined

all: run

SOURCES := $(COMPONENT)/proxy_core.cpp $(COMPONENT)/proxy_engine.cpp $(COMPONENT)/cs_sha256.cpp
HEADERS := $(COMPONENT)/proxy_core.h $(COMPONENT)/proxy_engine.h $(COMPONENT)/cs_sha256.h

host_proxy: host_proxy.cpp $(SOURCES) $(HEADERS)
	$(CXX) $(CXXFLAGS) -I$(COMPONENT) -o $@ host_proxy.cpp $(SOURCES)

run: host_proxy
	python3 -I test_host_proxy.py

clean:
	rm -f host_proxy

.PHONY: all run clean
