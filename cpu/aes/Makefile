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

aes_cbc:
	$(CXX) $(CFLAGS) -o aes_cbc$(EXT) aes_cbc.cpp

aes_ctr:
	$(CXX) $(CFLAGS) -o aes_ctr$(EXT) aes_ctr.cpp

all: aes_cbc aes_ctr

clean:
	rm -f aes_cbc aes_ctr aes_cbc.exe aes_ctr.exe