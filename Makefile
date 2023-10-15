CFLAGS:= -pedantic
EXEC:= dhcp-stats
default:= $(EXEC)
CC:=g++

$(EXEC): $(EXEC).o main.o dhcp.o
	$(CC) $(CFLAGS) -o $(EXEC) $(EXEC).cpp main.cpp dhcp.cpp -lpcap -lncurses
	
clean:
	rm -f *.o $(EXEC)

pack: clean
	tar -cvf xkubin27.tar * 

%.o: %.cpp %.hpp
	$(CC) $(CFLAGS) -c $<
