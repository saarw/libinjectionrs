CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -DLIBINJECTION_VERSION="\"dev\""
TARGET = debug_harness
SOURCE = debug_harness.c
XSS_TARGET = xss_debug_harness
XSS_SOURCE = xss_debug_harness.c

# Include path for libinjection-c
INCLUDE_DIR = ../../libinjection-c/src

.PHONY: all clean test xss

all: $(TARGET) $(XSS_TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -o $(TARGET) $(SOURCE)

$(XSS_TARGET): $(XSS_SOURCE)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -o $(XSS_TARGET) $(XSS_SOURCE)

xss: $(XSS_TARGET)

clean:
	rm -f $(TARGET) $(XSS_TARGET)

test: $(TARGET)
	@echo "Testing C harness..."
	@echo "SELECT * FROM users" | ./$(TARGET)
	@echo ""
	@echo "Testing with problematic input..."
	@echo "`n'#'" | ./$(TARGET)

install: $(TARGET)
	@echo "C tokenization harness built successfully"
	@echo "Usage: ./$(TARGET) \"input\" or echo \"input\" | ./$(TARGET)"