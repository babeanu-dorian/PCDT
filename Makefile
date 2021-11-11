CXX		  := g++
CXX_FLAGS := -O3 -Wall -Wextra -std=c++17 -ggdb

BIN		  := bin
SOURCEDIR := src
SRC		  := $(shell find $(SOURCEDIR) -name '*.cpp')
INCLUDE	  := include
LIB		  := lib

LIBRARIES	:= -lntl -pthread -lgmp -lhelib -lcryptopp
EXECUTABLE	:= main

all: $(BIN)/$(EXECUTABLE)

run: clean all
	clear
	./$(BIN)/$(EXECUTABLE)

$(BIN)/$(EXECUTABLE): $(SRC)
	export LD_LIBRARY_PATH=./$(LIB)
	$(CXX) $(CXX_FLAGS) -I$(INCLUDE) -L$(LIB) $^ -o $@ $(LIBRARIES) -Wl,--rpath=lib -Wl,--dynamic-linker=lib/ld-linux-x86-64.so.2

clean:
	-rm $(BIN)/*
