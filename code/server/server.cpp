#include "server.h"

static const char* NAME = "org.mp.fido";
static const char* PATH = "/org/mp/fido1";


int main(int argc, char *argv[])
{
    // Create D-Bus connection to the system bus and requests name on it.
    const char* serviceName = NAME;
    auto connection = sdbus::createSystemBusConnection(serviceName);

    // Create concatenator D-Bus object.
    const char* objectPath = PATH;
    Fido service(*connection, objectPath);

    // Run the loop on the connection.
    connection->enterEventLoop();
}