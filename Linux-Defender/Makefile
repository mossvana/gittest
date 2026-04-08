CC = gcc
CFLAGS = -Wall -Wextra -g
LIBS = -lssl -lcrypto -lcurl -lcjson -lyara -lm

TARGET = linux-defender

SRCS = main.c \
       threat_lookup.c \
       file_analysis.c \
       behavior_monitor.c \
       quarantine.c

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LIBS)

clean:
	rm -f $(TARGET)
