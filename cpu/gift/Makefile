CFLAGS = -O3 -ffast-math -flto -funroll-loops

# Detect OS
ifeq ($(OS),Windows_NT)
    EXT = .exe
    CXX = g++
else
    EXT =
    CXX = g++
    UNAME := $(shell uname -s)
    ifeq ($(UNAME),Darwin)
        # -march=native can cause issues on some macOS/Apple Silicon setups
        CFLAGS += -mcpu=native
    else
        CFLAGS += -march=native
    endif
endif

gift_cbc:
	$(CXX) $(CFLAGS) -o gift_cbc$(EXT) gift_cbc.cpp

gift_ctr:
	$(CXX) $(CFLAGS) -o gift_ctr$(EXT) gift_ctr.cpp

all: gift_cbc gift_ctr

clean:
	rm -f gift_cbc gift_ctr gift_cbc.exe gift_ctr.exe