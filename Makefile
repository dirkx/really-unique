
all: generate

generate: generate.c
	cc -I/opt/local/include -L/opt/local/lib -o generate generate.c -lcrypto 

test:	generate
	./generate 10 | hexdump

clean:
	rm -f generate.o  generate
