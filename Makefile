CC = clang
CFLAGS	= -O2 -Wall -DDEBUG -g
INCLUDES = -I./ -I./readline -I./include
LFLAGS = -L./readline/shlib
LIBS =	-lwolfssl 			\
	-lncurses			\
	-lreadline

all:
	$(CC) $(CFLAGS) $(INCLUDES) -o rat src/rat.c $(LFLAGS) $(LIBS) src/compression.c
	#src/file_operations.c src/compression.c
	#$(CC) $(CFLAGS) $(INCLUDES) -o rat-client src/rat-client.c $(LFLAGS) $(LIBS) src/file_operations-client.c src/compression.c

clean:
	rm -f rat rat-client
