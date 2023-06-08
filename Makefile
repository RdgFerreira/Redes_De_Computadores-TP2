all:
	gcc -Wall -pthread user.c -o user
	gcc -Wall -pthread server.c -o server