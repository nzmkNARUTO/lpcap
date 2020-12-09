app:app.c app.h pcap ppro pcot util
	@gcc -o pcap app.c util.o -L./lib -lpcap -lppro -lpcot -lncurses
pcap:pcap.c pcap.h
	@gcc -c pcap.c -shared -fPIC -o ./lib/libpcap.so
ppro:ppro.c ppro.h
	@gcc -c ppro.c -shared -fPIC -o ./lib/libppro.so
pcot:pcot.c pcot.h
	@gcc -c pcot.c -shared -fPIC -o ./lib/libpcot.so
util:util.c util.h
	@gcc -c util.c -o util.o
clean:
	@-rm ./lib/* pcap util.o