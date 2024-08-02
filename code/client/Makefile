# Compiler and flags
CXX = g++
CXXFLAGS = -Wall -fPIC
INCLUDES = -I/usr/include/dbus-1.0 -I/usr/lib/x86_64-linux-gnu/dbus-1.0/include
LDFLAGS = -shared 

# Source and object files
SRCS = fido.cpp
OBJS = $(SRCS:.cpp=.o)

# Output library
TARGET = libfido-dbus.so

# Default rule
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^ 

# Rule for compiling source files into object files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# Clean rule
clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: all clean
