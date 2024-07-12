# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Wextra -std=c11

# Source files
SRC = $(wildcard *.c)

# Object files
OBJ = $(SRC:.c=.o)

# Executable
EXEC = my_program

# Log file
LOGFILE = build_log.txt
JSONFILE = build_report.json

# Default target
all: clean $(EXEC) report

# Build the executable
$(EXEC): $(OBJ)
	@echo "Linking object files to create the executable..."
	-$(CC) $(CFLAGS) -o $@ $^ > $(LOGFILE) 2>&1 || true
	@echo "Build completed with or without errors."

# Build object files
%.o: %.c
	@echo "Compiling $<..."
	-$(CC) $(CFLAGS) -c $< -o $@ >> $(LOGFILE) 2>&1 || true

# Create a JSON report from the log file
report:
	@echo '{ "warnings":[' > $(JSONFILE)
	@awk '/warning:/ { gsub(/"/, "\\\"", $$0); if (NR!=1) printf ","; printf "{\"file\":\"%s\",\"output\":\"%s\"}", FILENAME, $$0 }' $(LOGFILE) >> $(JSONFILE)
	@echo '], "errors":[' >> $(JSONFILE)
	@awk '/error:/ { gsub(/"/, "\\\"", $$0); if (NR!=1) printf ","; printf "{\"file\":\"%s\",\"output\":\"%s\"}", FILENAME, $$0 }' $(LOGFILE) >> $(JSONFILE)
	@echo ']}' >> $(JSONFILE)

# Clean up build files
clean:
	rm -f $(OBJ) $(EXEC) $(LOGFILE) $(JSONFILE)

.PHONY: all clean report
