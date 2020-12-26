app:app.c app.h util capture analysis statistic
	@gcc -o sniffer app.c util.o capture.o analysis.o statistic.o -lncursesw -lpcap -lpthread
capture:capture.c capture.h
	@gcc -c capture.c -o capture.o
analysis:analysis.c analysis.h
	@gcc -c analysis.c -o analysis.o
statistic:statistic.c statistic.h
	@gcc -c statistic.c -o statistic.o
util:util.c util.h
	@gcc -c util.c -o util.o
clean:temp
	@-rm ./*.o sniffer
temp:
	@-rm -f temp.pcap