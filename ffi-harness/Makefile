CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O3 -fno-omit-frame-pointer -g -fPIC -DLIBINJECTION_VERSION=\"3.10.0\"
INCLUDES = -I../libinjection-c/src
SRCDIR = ../libinjection-c/src
OBJDIR = obj
LIBDIR = lib

# Source files from libinjection
SOURCES = $(SRCDIR)/libinjection_sqli.c $(SRCDIR)/libinjection_xss.c $(SRCDIR)/libinjection_html5.c
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

# Target library
LIBRARY = $(LIBDIR)/libinjection_harness.a
SHARED_LIB = $(LIBDIR)/libinjection_harness.so

# Harness wrapper
HARNESS_SRC = harness.c
HARNESS_OBJ = $(OBJDIR)/harness.o

all: $(LIBRARY) $(SHARED_LIB)

# Create directories
$(OBJDIR):
	mkdir -p $(OBJDIR)

$(LIBDIR):
	mkdir -p $(LIBDIR)

# Compile libinjection objects
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Compile harness wrapper
$(HARNESS_OBJ): $(HARNESS_SRC) | $(OBJDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Create static library
$(LIBRARY): $(OBJECTS) $(HARNESS_OBJ) | $(LIBDIR)
	ar rcs $@ $(OBJECTS) $(HARNESS_OBJ)

# Create shared library
$(SHARED_LIB): $(OBJECTS) $(HARNESS_OBJ) | $(LIBDIR)
	$(CC) -shared $(OBJECTS) $(HARNESS_OBJ) -o $@

clean:
	rm -rf $(OBJDIR) $(LIBDIR)

.PHONY: all clean