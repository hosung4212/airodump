CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -Wpedantic -O2 -pthread
LDLIBS := -lpcap -lncurses

TARGET := airodump
SOURCES := main.cpp mac_utils.cpp radiotap.cpp dot11_frame.cpp channel_hopper.cpp ui.cpp
OBJECTS := $(SOURCES:.cpp=.o)
HEADERS := types.h byte_utils.h mac_utils.h radiotap.h dot11_frame.h channel_hopper.h ui.h

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	$(RM) $(TARGET) $(OBJECTS)
