build:
build-shared:
	mkdir -p build
	gcc -c -fpic src/zprotocol.c -o build/zprotocol.o
	gcc -shared -o build/libzprotocol.so build/zprotocol.o -lsodium
	rm -f build/zprotocol.o

	mkdir -p build/include build/lib
	cp build/libzprotocol.so build/lib
	cp src/zprotocol.h build/include/

build-static:
	mkdir -p build
	gcc -c src/zprotocol.c -o build/zprotocol.o
	ar rs build/libzprotocol.a build/zprotocol.o
	rm -f build/zprotocol.o

	mkdir -p include lib
	cp build/libzprotocol.a build/lib
	cp src/zprotocol.h build/include

install:
	sudo cp build/libzprotocol.so /usr/lib/
	sudo cp build/include/zprotocol.h /usr/include

remove:
	sudo rm -f /usr/lib/libzprotocol.so
	sudo rm -f /usr/include/zprotocol.h

clean:
	sudo rm -rf build

backup:
	mkdir -p ../zprotocol_backup && \
	cd ../zprotocol_backup && \
	cp -R ../zprotocol "zprotocol_backup_$$(date "+%Y-%m-%d_%H%M%S")"

build-example:
	mkdir -p build
	gcc example/sync-client.c src/* -lpthread -lsodium -o build/sync-client
	gcc example/sync-server.c src/* -lpthread -lsodium -o build/sync-server
	gcc example/concurrent-client.c src/* -lpthread -lsodium -o build/concurrent-client
	gcc example/concurrent-server.c src/* -lpthread -lsodium -o build/concurrent-server

build-test:
	mkdir -p build
	gcc test/test.c src/* -lpthread -lsodium -o build/test
