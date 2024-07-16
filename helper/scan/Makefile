# Define the compiler
CC = gcc

# Find all .c files in subdirectories
SRC_FILES := $(shell find . -name '*.c')

# Define the log file
LOG_FILE = compile_errors.log

# Define the default target
all: compile_all

# Define the compilation rule
compile_all:
	@> $(LOG_FILE) # Clear the log file
	@for src in $(SRC_FILES); do \
		echo "Compiling $$src..."; \
		$(CC) -o $$(dirname $$src)/$$(basename $$src .c).out $$src 2>> $(LOG_FILE) || true; \
	done

# Define a clean rule
clean:
	find . -name '*.out' -exec rm -f {} \;

# Always return exit code 0
.PHONY: all compile_all clean
