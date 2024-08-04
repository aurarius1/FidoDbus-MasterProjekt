CXX := g++
LIB_DIR = /usr/lib

CXXFLAGS := -std=c++17 -Wall -Wextra -I$(LIB_DIR)  # Include directory for library headers
LDFLAGS := -L$(LIB_DIR) -llibwebauthn_bridge  # Library linking flags

SERVER_SRC := server/server.cpp
ADAPTOR_HEADER := server/fido-server-glue.h
PROXY_HEADER := client/fido-client-glue.h
XML_FILE := org.mp.fido.xml

SERVER_EXEC := server/dbus-org.mp.fido.server

all: $(PROXY_HEADER) $(ADAPTOR_HEADER) $(SERVER_EXEC) #$(CLIENT_EXEC)
adaptor: $(ADAPTOR_HEADER)
proxy: $(PROXY_HEADER)

$(SERVER_EXEC): $(SERVER_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) `pkg-config sdbus-c++ --cflags --libs` 

$(ADAPTOR_HEADER): $(XML_FILE)
	sdbus-c++-xml2cpp $(XML_FILE) --adaptor=$(ADAPTOR_HEADER) 

$(PROXY_HEADER): $(XML_FILE)
	sdbus-c++-xml2cpp $(XML_FILE) --proxy=$(PROXY_HEADER) 

clean:
	$(RM) $(SERVER_EXEC) $(CLIENT_EXEC) $(ADAPTOR_HEADER)

.PHONY: all clean
