// Adapted from node-opcua sample client
// https://github.com/node-opcua/node-opcua/blob/master/documentation/sample_client.js

const opcua = require("node-opcua");
const async = require("async");

const client = opcua.OPCUAClient.create({
    applicationName: "ClientSample",
    connectionStrategy: {
        initialDelay: 1000,
        maxRetry: 1
    },
    securityMode: opcua.MessageSecurityMode.None,
    securityPolicy: opcua.SecurityPolicy.None,
    endpoint_must_exist: false,
});
const endpointUrl = "opc.tcp://127.0.0.1:4855/";

let the_session, subscription;

const node_id = "ns=2;s=v1";

async.series([
        // step 1 : connect to
        callback => {
            client.connect(endpointUrl, err => {
                if (err) {
                    console.log(" cannot connect to endpoint :", endpointUrl);
                } else {
                    console.log("connected !");
                }
                callback(err);
            });
        },

        // step 2 : createSession
        callback => {
            client.createSession((err, session) => {
                if (!err) {
                    the_session = session;
                }
                callback(err);
            });
        },

        // step 3 : browse
        callback => {
            the_session.browse("RootFolder", (err, browse_result) => {
                if (!err) {
                    console.log("STEP 3 " + JSON.stringify(browse_result));
                    browse_result.references.forEach(reference => {
                        console.log(reference.browseName.toString());
                    });
                }
                callback(err);
            });
        },

        // step 4 : read a variable with readVariableValue
        callback => {
            the_session.readVariableValue(node_id, (err, dataValue) => {
                if (!err) {
                    console.log(" free mem % = ", dataValue.toString());
                }
                callback(err);
            });


        },

        // step 4' : read a variable with read
        callback => {
            const max_age = 0;
            const nodes_to_read = [
                {nodeId: node_id, attributeId: opcua.AttributeIds.Value}
            ];
            the_session.read(nodes_to_read, max_age, (err, nodes_to_read, dataValues) => {
                if (!err) {
                    console.log(" free mem % = ", dataValues);
                }
                callback(err);
            });
        },

        // step 5: install a subscription and install a monitored item for 10 seconds
        callback => {
            subscription = opcua.ClientSubscription.create(the_session, {
                requestedPublishingInterval: 1000,
                requestedLifetimeCount: 10,
                requestedMaxKeepAliveCount: 2,
                maxNotificationsPerPublish: 10,
                publishingEnabled: true,
                priority: 10
            });

            subscription.on("started", () => {
                console.log("subscription started for 2 seconds - subscriptionId=", subscription.subscriptionId);
            }).on("keepalive", () => {
                console.log("keepalive");
            }).on("terminated", () => {
                callback();
            });

            setTimeout(() => {
                subscription.terminate();
            }, 10000);

            // install monitored item
            const monitoredItem = opcua.ClientMonitoredItem.create(
                subscription,
                {
                    nodeId: opcua.resolveNodeId(node_id),
                    attributeId: opcua.AttributeIds.Value
                },
                {
                    samplingInterval: 100,
                    discardOldest: true,
                    queueSize: 10
                },
                opcua.TimestampsToReturn.Both);
            console.log("-------------------------------------");

            monitoredItem.on("changed", (dataValue) => {
                console.log(" v1 = ", dataValue.value.value);
            });
        },

        // close session
        callback => {
            the_session.close(err => {
                if (err) {
                    console.log("session closed failed ?");
                }
                callback();
            });
        }

    ],
    err => {
        if (err) {
            console.log(" failure ", err);
        } else {
            console.log("done!");
        }
        client.disconnect(() => {
        });
    });
