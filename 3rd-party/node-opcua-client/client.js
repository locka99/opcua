// Adapted from node-opcua sample client
// https://github.com/node-opcua/node-opcua/blob/master/documentation/sample_client.js

var opcua = require("node-opcua");
var async = require("async");

var client = new opcua.OPCUAClient();
var endpointUrl = "opc.tcp://127.0.0.1:4855/";

var the_session, the_subscription;

var node_id = "ns=2;s=v1";

async.series([
        // step 1 : connect to
        function (callback) {
            client.connect(endpointUrl, function (err) {
                if (err) {
                    console.log(" cannot connect to endpoint :", endpointUrl);
                } else {
                    console.log("connected !");
                }
                callback(err);
            });
        },

        // step 2 : createSession
        function (callback) {
            client.createSession(function (err, session) {
                if (!err) {
                    the_session = session;
                }
                callback(err);
            });
        },

        // step 3 : browse
        function (callback) {
            the_session.browse("RootFolder", function (err, browse_result) {
                if (!err) {
                    browse_result[0].references.forEach(function (reference) {
                        console.log(reference.browseName.toString());
                    });
                }
                callback(err);
            });
        },

        // step 4 : read a variable with readVariableValue
        function (callback) {
            the_session.readVariableValue(node_id, function (err, dataValue) {
                if (!err) {
                    console.log(" free mem % = ", dataValue.toString());
                }
                callback(err);
            });


        },

        // step 4' : read a variable with read
        function (callback) {
            var max_age = 0;
            var nodes_to_read = [
                {nodeId: node_id, attributeId: opcua.AttributeIds.Value}
            ];
            the_session.read(nodes_to_read, max_age, function (err, nodes_to_read, dataValues) {
                if (!err) {
                    console.log(" free mem % = ", dataValues[0]);
                }
                callback(err);
            });
        },

        // step 5: install a subscription and install a monitored item for 10 seconds
        function (callback) {
            the_subscription = new opcua.ClientSubscription(the_session, {
                requestedPublishingInterval: 1000,
                requestedLifetimeCount: 10,
                requestedMaxKeepAliveCount: 2,
                maxNotificationsPerPublish: 10,
                publishingEnabled: true,
                priority: 10
            });

            the_subscription.on("started", function () {
                console.log("subscription started for 2 seconds - subscriptionId=", the_subscription.subscriptionId);
            }).on("keepalive", function () {
                console.log("keepalive");
            }).on("terminated", function () {
                callback();
            });

            setTimeout(function () {
                the_subscription.terminate();
            }, 10000);

            // install monitored item
            var monitoredItem = the_subscription.monitor({
                    nodeId: opcua.resolveNodeId(node_id),
                    attributeId: opcua.AttributeIds.Value
                },
                {
                    samplingInterval: 100,
                    discardOldest: true,
                    queueSize: 10
                },
                opcua.read_service.TimestampsToReturn.Both
            );
            console.log("-------------------------------------");

            monitoredItem.on("changed", function (dataValue) {
                console.log(" % free mem = ", dataValue.value.value);
            });
        },

        // close session
        function (callback) {
            the_session.close(function (err) {
                if (err) {
                    console.log("session closed failed ?");
                }
                callback();
            });
        }

    ],
    function (err) {
        if (err) {
            console.log(" failure ", err);
        } else {
            console.log("done!");
        }
        client.disconnect(function () {
        });
    });
