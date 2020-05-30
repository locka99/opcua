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

    auto *server = UA_Server_new();
    UA_ServerConfig_setDefault(UA_Server_getConfig(server));

    // Add some variables (NOTE this code is not going to free any memory but for this simple example that does not matter)
    auto idx = UA_Server_addNamespace(server, "foo");
    addVariable(server, idx, "v1", UA_TYPES_INT32);
    addVariable(server, idx, "v2", UA_TYPES_BOOLEAN);
    addVariable(server, idx, "v3", UA_TYPES_STRING);
    addVariable(server, idx, "v4", UA_TYPES_DOUBLE);

    // TODO timers to change values

    UA_Server_run(server, &running);
    UA_Server_delete(server);
    return 0;
}