all: airodump

airodump: main.o 
	gcc -o airodump main.o -lpcap

main.o: main.cpp
	g++ -c -o main.o main.cpp 
	
clean:
	rm -f airodump *.o