// MODIFIED FROM open62541 example

#ifdef _WIN32

#include <winsock2.h>
#include <windows.h>

void my_sleep_ms(unsigned long ms) {
    ::Sleep(ms);
}

#define UA_sleep_ms(X) my_sleep_ms(X)
#else
# include <unistd.h>
# define UA_sleep_ms(X) usleep(X * 1000)
#endif

#include <signal.h>
#include <stdlib.h>

#include <open62541/types.h>
#include <open62541/client.h>
#include <open62541/client_subscriptions.h>
#include <open62541/client_config.h>
#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/plugin/log_stdout.h>

UA_Boolean running = true;
const UA_Logger *logger = UA_Log_Stdout;

static void stopHandler(int sign) {
    UA_LOG_INFO(logger, UA_LOGCATEGORY_USERLAND, "Received Ctrl-C");
    running = 0;
}

static void
handler_valueChanged(UA_Client *client, UA_UInt32 subId, void *subContext,
                     UA_UInt32 monId, void *monContext, UA_DataValue *value) {
    UA_LOG_INFO(logger, UA_LOGCATEGORY_USERLAND, "value has changed!");
    if (UA_Variant_hasScalarType(&value->value, &UA_TYPES[UA_TYPES_INT32])) {
        UA_Int32 rawValue = *(UA_Int32 *) value->value.data;
        UA_LOG_INFO(logger, UA_LOGCATEGORY_USERLAND, "value is %d", rawValue);
    }
}

static void
deleteSubscriptionCallback(UA_Client *client, UA_UInt32 subscriptionId, void *subscriptionContext) {
    UA_LOG_INFO(logger, UA_LOGCATEGORY_USERLAND, "Subscription Id %u was deleted", subscriptionId);
}

static void
subscriptionInactivityCallback(UA_Client *client, UA_UInt32 subId, void *subContext) {
    UA_LOG_INFO(logger, UA_LOGCATEGORY_USERLAND, "Inactivity for subscription %u", subId);
}

static void
stateCallback(UA_Client *client, UA_ClientState clientState) {
    switch (clientState) {
        case UA_CLIENTSTATE_DISCONNECTED:
            UA_LOG_INFO(logger, UA_LOGCATEGORY_USERLAND, "The client is disconnected");
            break;
        case UA_CLIENTSTATE_CONNECTED:
            UA_LOG_INFO(logger, UA_LOGCATEGORY_USERLAND, "A TCP connection to the server is open");
            break;
        case UA_CLIENTSTATE_SECURECHANNEL:
            UA_LOG_INFO(logger, UA_LOGCATEGORY_USERLAND, "A SecureChannel to the server is open");
            break;
        case UA_CLIENTSTATE_SESSION: {
            UA_LOG_INFO(logger, UA_LOGCATEGORY_USERLAND, "A session with the server is open");
            /* A new session was created. We need to create the subscription. */
            /* Create a subscription */
            UA_CreateSubscriptionRequest request = UA_CreateSubscriptionRequest_default();
            UA_CreateSubscriptionResponse response = UA_Client_Subscriptions_create(client, request,
                                                                                    NULL, NULL,
                                                                                    deleteSubscriptionCallback);

            if (response.responseHeader.serviceResult == UA_STATUSCODE_GOOD)
                UA_LOG_INFO(logger, UA_LOGCATEGORY_USERLAND, "Create subscription succeeded, id %u",
                            response.subscriptionId);
            else
                return;

            /* Add a MonitoredItem */

            char *node_id = const_cast<char *>("v1");

            UA_MonitoredItemCreateRequest monRequest =
                    UA_MonitoredItemCreateRequest_default(UA_NODEID_STRING(2, node_id));

            UA_MonitoredItemCreateResult monResponse =
                    UA_Client_MonitoredItems_createDataChange(client, response.subscriptionId,
                                                              UA_TIMESTAMPSTORETURN_BOTH,
                                                              monRequest, NULL, handler_valueChanged, NULL);
            if (monResponse.statusCode == UA_STATUSCODE_GOOD)
                UA_LOG_INFO(logger, UA_LOGCATEGORY_USERLAND,
                            "Monitoring ns=2;s=v1', id %u", monResponse.monitoredItemId);
        }
            break;
        case UA_CLIENTSTATE_SESSION_RENEWED:
            UA_LOG_INFO(logger, UA_LOGCATEGORY_USERLAND, "A session with the server is open (renewed)");
            /* The session was renewed. We don't need to recreate the subscription. */
            break;
        default:
            exit(1);
    }
    return;
}

int main(void) {
    signal(SIGINT, stopHandler); /* catches ctrl-c */

    UA_Client *client = UA_Client_new();

    UA_ClientConfig *config = UA_Client_getConfig(client);
    /* Set stateCallback */
    config->stateCallback = stateCallback;
    config->subscriptionInactivityCallback = subscriptionInactivityCallback;

    UA_ClientConfig_setDefault(config);

    /* Endless loop runAsync */
    while (running) {
        /* if already connected, this will return GOOD and do nothing */
        /* if the connection is closed/errored, the connection will be reset and then reconnected */
        /* Alternatively you can also use UA_Client_getState to get the current state */
        UA_StatusCode retval = UA_Client_connect(client, "opc.tcp://localhost:4855");
        if (retval != UA_STATUSCODE_GOOD) {
            UA_LOG_ERROR(logger, UA_LOGCATEGORY_USERLAND, "Not connected. Retrying to connect in 1 second");
            /* The connect may timeout after 5 seconds (default timeout) or it may fail immediately on network errors */
            /* E.g. name resolution errors or unreachable network. Thus there should be a small sleep here */
            UA_sleep_ms(1000);
            continue;
        }

        UA_Client_run_iterate(client, 1000);
    };

    /* Clean up */
    UA_Client_delete(client); /* Disconnects the client internally */
    return UA_STATUSCODE_GOOD;
}