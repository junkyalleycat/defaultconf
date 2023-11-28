src/defaultconf/_bsdnet.cpython-39.so: _bsdnet.c
	cc -g -fPIC -shared `pkgconf python-3.9 --cflags` _bsdnet.c -o src/defaultconf/_bsdnet.cpython-39.so
