output = src/defaultconf/_bsdnet.cpython-39.so

$(output): _bsdnet.c
	cc -g -fPIC -shared `pkgconf python-3.9 --cflags` $(.ALLSRC) -o $(.TARGET)

clean:
	rm $(output)

