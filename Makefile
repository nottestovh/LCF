CC      = gcc
CFLAGS  = -Wall -Wextra -O2
BUILD   = build
BIN     = bin

SERVER_SRCS = server/main.c server/rr.c
CLIENT_SRCS = client/main.c

SERVER_OBJS = $(SERVER_SRCS:%.c=$(BUILD)/%.o)
CLIENT_OBJS = $(CLIENT_SRCS:%.c=$(BUILD)/%.o)

SERVER_BIN = $(BIN)/server
CLIENT_BIN = $(BIN)/client

all: $(SERVER_BIN) $(CLIENT_BIN)

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(SERVER_BIN): $(SERVER_OBJS)
	@mkdir -p $(BIN)
	$(CC) $(CFLAGS) $^ -o $@

$(CLIENT_BIN): $(CLIENT_OBJS)
	@mkdir -p $(BIN)
	$(CC) $(CFLAGS) $^ -o $@

server: $(SERVER_BIN)
client: $(CLIENT_BIN)

clean:
	rm -rf $(BUILD) $(BIN)

.PHONY: all clean server client

