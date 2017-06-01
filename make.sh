gcc -Wall -fPIC -shared -o ld_quobyte.so ld_quobyte.c -lquobyte
gcc -Wall -fPIC -shared -DDEBUG -o ld_quobyte_debug.so ld_quobyte.c -lquobyte
