src/defaultconf/_bsdnetlink.cpython-39.so: _bsdnetlink.c
	cc -g -fPIC -shared `pkgconf python-3.9 --cflags` _bsdnetlink.c -o src/defaultconf/_bsdnetlink.cpython-39.so
