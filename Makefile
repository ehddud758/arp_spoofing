arp_spoof: main.o ip.o infofetcher.o mac.o arp.o
	g++ main.o ip.o infofetcher.o mac.o arp.o -o arp_spoof -std=c++11 -lpcap -Wall -lpthread
main.o: main.cpp
	g++ -o main.o -c main.cpp -std=c++11 -lpcap -Wall -lpthread
ip.o: ip.h
	g++ -o ip.o -c ip.cpp -std=c++11 -Wall
infofetcher.o: infofetcher.cpp
	g++ -o infofetcher.o -c infofetcher.cpp -std=c++11 -Wall
mac.o: mac.cpp
	g++ -o mac.o -c mac.cpp -std=c++11 -Wall
arp.o: arp.cpp
	g++ -o arp.o -c arp.cpp -std=c++11 -Wall

clean:
	rm *.o arp_spoof
