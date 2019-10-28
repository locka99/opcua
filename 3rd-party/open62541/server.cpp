#include <signal.h>
#include <string>
#include <thread>

#include "libopen62541/open62541.h"

// This is mostly cut and pasted together from tutorials to mimic the same behaviour as found in simple-server
// and the node-opcua/server.js
//
// "ns=2;s=v1", Int32, increments every 500ms
// "ns=2;s=v2", Boolean, flips every 500ms
// "ns=2;s=v3", String, says "Hello world times X" every 1000ms where X is an incrementing value
// "ns=2;s=v4", Double, sinewave changes every 1000ms - sin((X % 360) * Math.PI / 180.0);

UA_Boolean running = true;

static void stopHandler(int sig) {
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "received ctrl-c");
    running = false;
}

static void
addVariable(UA_Server *server, short nsIdx, const std::string &name, int type) {
    /* Define the attribute of the myInteger variable node */
    auto attr = UA_VariableAttributes_default;
    attr.description = UA_LOCALIZEDTEXT_ALLOC("en-US", name.c_str());
    attr.displayName = UA_LOCALIZEDTEXT_ALLOC("en-US", name.c_str());
    attr.dataType = UA_TYPES[type].typeId;
    attr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;

    /* Add the variable node to the information model */
    auto nodeId = UA_NODEID_STRING_ALLOC(nsIdx, name.c_str());
    auto qualifiedName = UA_QUALIFIEDNAME_ALLOC(nsIdx, name.c_str());
    auto parentNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER);
    auto parentReferenceNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES);
    UA_Server_addVariableNode(server, nodeId, parentNodeId,
                              parentReferenceNodeId, qualifiedName,
                              UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE), attr, NULL, NULL);
}

int main(void) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    auto *config = UA_ServerConfig_new_minimal(4855, NULL);
    auto *server = UA_Server_new(config);

    // Add some variables
    UA_Server_addNamespace(server, "foo");
    addVariable(server, 2, "v1", UA_TYPES_INT32);
    addVariable(server, 2, "v2", UA_TYPES_BOOLEAN);
    addVariable(server, 2, "v3", UA_TYPES_STRING);
    addVariable(server, 2, "v4", UA_TYPES_DOUBLE);

    // TODO timers to change values

    auto retval = UA_Server_run(server, &running);
    UA_Server_delete(server);
    UA_ServerConfig_delete(config);
    return (int) retval;
}