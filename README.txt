Overall:

This task includes a stack server (component I) implementing multi
process shared memory and locking routines.
We upgraded it just like in previous assignment, to work with spells, charms and
other cool stuffs from Harry Potter =]


References:
    0. Using fcntl library lock: 
    https://www.informit.com/articles/article.aspx?p=23618&seqNum=4#:~:text=The%20fcntl%20system%20call%20allows,on%20a%20writable%20file%20descriptor.

    1. malloc, free, calloc implementations:
         https://github.com/chrisvrose/os3-malloc-mmap/blob/master/src/mapmanagement.c

Running server and clients:

In each time we want to connect to the server from another client, only one can be connected 
and send a command to the server.
Only when the first client finished his job, the next client in line can "take" the flock and executes on his own,
and so forth...



Submitted by: 311382360 Eran Levy _ 315524389 Or Mendel