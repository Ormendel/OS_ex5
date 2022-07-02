CC=g++

FLAGS= -Wall -g


all: server client

server: server.cpp stack_list.hpp

	$(CC) $(FLAGS) server.cpp stack_list.hpp -o server

client: client.cpp

	$(CC) $(FLAGS) client.cpp -o client

.PHONY: clean all

clean:
	rm -f *.o *.a server client
