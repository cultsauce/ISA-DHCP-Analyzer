CFLAGS:= -pedantic
EXEC:= dhcp-stats
default:= $(EXEC)
CC:=g++

$(EXEC): $(EXEC).o main.o dhcp.o subnet.o
	$(CC) $(CFLAGS) -o $(EXEC) $(EXEC).cpp main.cpp subnet.cpp dhcp.cpp -lpcap -lncurses
	
clean:
	rm -f *.o $(EXEC)

pack: clean
	tar -cvf xkubin27.tar dhcp-stats.* dhcp.* subnet.* main.cpp README.md examples Makefile

%.o: %.cpp %.hpp
	$(CC) $(CFLAGS) -c $<
