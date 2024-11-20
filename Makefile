build:
build-shared:
	mkdir -p build
	gcc -c -fpic src/zprotocol.c -o build/zprotocol.o
	gcc -c -fpic src/helpers.c -o build/helpers.o
	gcc -c -fpic src/utils.c -o build/utils.o
	gcc -shared -o build/libzprotocol.so build/*.o -lsodium
	rm -f build/*.o

	mkdir -p build/include build/lib
	cp build/libzprotocol.so build/lib/
	cp src/zprotocol.h build/include/

build-static:
	mkdir -p build
	gcc -c src/zprotocol.c -o build/zprotocol.o
	gcc -c src/helpers.c -o build/helpers.o
	gcc -c src/utils.c -o build/utils.o
	ar rs build/libzprotocol.a build/*.o
	rm -f build/*.o

	mkdir -p build/include build/lib
	cp build/libzprotocol.a build/lib/
	cp src/zprotocol.h build/include/

install:
	cp build/libzprotocol.so /usr/lib/
	cp build/include/zprotocol.h /usr/include

install-static:
	cp build/libzprotocol.a /usr/lib/
	cp build/include/zprotocol.h /usr/include

remove:
	rm -f /usr/lib/libzprotocol.so
	rm -f /usr/lib/libzprotocol.a
	rm -f /usr/include/zprotocol.h

clean:
	rm -rf build

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
