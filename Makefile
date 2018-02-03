CC = gcc
CFLAGS = -g -Wall -lpcap -lm
TARGET = kerb

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).c

clean:
	$(RM) $(TARGET)
