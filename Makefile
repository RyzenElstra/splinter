CC = clang
CFLAGS	= -O2 -Wall -DDEBUG -g
INCLUDES = -I./mbedtls/include -I./ -I./readline -I./include
LFLAGS = -L./mbedtls/library	\
	 -L./readline/shlib
LIBS =	-lmbedtls 			\
	-lmbedx509			\
	-lmbedcrypto			\
	-lncurses			\
	-lreadline

all:
	$(CC) $(CFLAGS) $(INCLUDES) -o rat src/rat.c $(LFLAGS) $(LIBS) src/file_operations.c src/compression.c
	$(CC) $(CFLAGS) $(INCLUDES) -o rat-client src/rat-client.c $(LFLAGS) $(LIBS) src/file_operations-client.c src/compression.c

clean:
	rm -f rat rat-client
