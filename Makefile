CC = clang
CFLAGS	= -O2 -Wall -DDEBUG -g
INCLUDES = -I./mbedtls/include -I./src/client -I./src/server -I./readline -I./
LFLAGS = -L./mbedtls/library	\
	 -L./readline/shlib
LIBS =	-lmbedtls 			\
	-lmbedx509			\
	-lmbedcrypto			\
	-lncurses			\
	-lreadline

all:
	$(CC) $(CFLAGS) $(INCLUDES) -o rat src/server/rat.c $(LFLAGS) $(LIBS) src/server/file_operations.c src/compression.c
	$(CC) $(CFLAGS) $(INCLUDES) -o rat-client src/client/rat-client.c $(LFLAGS) $(LIBS) src/client/file_operations-client.c src/compression.c

clean:
	rm -f rat rat-client
