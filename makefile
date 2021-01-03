sniffer: app capture analysis statistic util
	@gcc -o sniffer app.o util.o capture.o analysis.o statistic.o -lncursesw -lpcap -lpthread --no-warnings
	@echo "LINK: app.o util.o capture.o analysis.o statistic.o => sniffer (with lncursesw lpcap lpthread)"
app:app.c app.h
	@gcc -c app.c -o app.o --no-warnings
	@echo "COMPILE: app.c app.h => app.o"
capture:capture.c capture.h
	@gcc -c capture.c -o capture.o --no-warnings
	@echo "COMPILE: capture.c capture.h => capture.o"
analysis:analysis.c analysis.h
	@gcc -c analysis.c -o analysis.o --no-warnings
	@echo "COMPILE: analysis.c analysis.h => analysis.o"
statistic:statistic.c statistic.h
	@gcc -c statistic.c -o statistic.o --no-warnings
	@echo "COMPILE: statistic.c statistic.h => statistic.o"
util:util.c util.h
	@gcc -c util.c -o util.o --no-warnings
	@echo "COMPILE: util.c util.h => util.o"
clean:temp
	@-rm ./*.o sniffer
temp:
	@-rm -f temp.pcap