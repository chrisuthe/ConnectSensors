# Needs Python with cryptography and websockets.
all: run

../host_proxy/host_proxy:
	$(MAKE) -C ../host_proxy host_proxy

run: ../host_proxy/host_proxy
	python3 -I test_mailbox.py
	python3 -I test_two_homes.py

.PHONY: all run
