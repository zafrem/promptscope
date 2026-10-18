NATIVE := python/src/promptscope/_native
UNAME  := $(shell uname -s)
ifeq ($(UNAME),Darwin)
LIB := libpromptscope.dylib
else ifneq (,$(findstring MINGW,$(UNAME)))
LIB := promptscope.dll
else
LIB := libpromptscope.so
endif

.PHONY: test lib python-test wheel clean

test:
	go vet ./...
	go test -race ./...

lib:
	mkdir -p $(NATIVE)
	go build -buildmode=c-shared -o $(NATIVE)/$(LIB) ./capi

python-test: lib
	cd python && python3 -m pytest -q

wheel: lib
	cd python && python3 -m pip wheel . --no-deps -w dist

clean:
	rm -rf $(NATIVE) python/dist python/build python/src/*.egg-info
