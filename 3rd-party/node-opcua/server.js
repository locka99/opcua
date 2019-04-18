/*global require,setInterval,console */
var opcua = require("node-opcua");

// Let's create an instance of OPCUAServer
var server = new opcua.OPCUAServer({
    securityPolicies: [opcua.SecurityPolicy.None, opcua.SecurityPolicy.Basic128Rsa15, opcua.SecurityPolicy.Basic256, opcua.SecurityPolicy.Basic256Sha256],
    securityModes: [opcua.MessageSecurityMode.NONE, opcua.MessageSecurityMode.SIGN, opcua.MessageSecurityMode.SIGNANDENCRYPT],
    port: 4855, // the port of the listening socket of the server
    resourcePath: "", // this path will be added to the endpoint resource name
    buildInfo: {
        productName: "Node OPCUA Server",
        buildNumber: "7658",
        buildDate: new Date(2014, 5, 2)
    },
    alternateHostname: "127.0.0.1"
});

function post_initialize() {
    console.log("initialized");

    function construct_my_address_space(server) {

        var addressSpace = server.engine.addressSpace;

        // declare a new object
        var sampleDir = addressSpace.addObject({
            organizedBy: addressSpace.rootFolder.objects,
            browseName: "Sample"
        });

        // int, bool, string, double

        var v1 = 100;
        addressSpace.addVariable({
            componentOf: sampleDir,
            nodeId: "ns=2;s=v1",
            browseName: "v1",
            dataType: "Int32",
            value: {
                get: () => new opcua.Variant({dataType: opcua.DataType.Int32, value: v1})
            }
        });


        var v2 = false;
        addressSpace.addVariable({
            componentOf: sampleDir,
            nodeId: "ns=2;s=v2",
            browseName: "v2",
            dataType: "Boolean",
            value: {
                get: () => new opcua.Variant({dataType: opcua.DataType.Boolean, value: v2})
            }
        });


        // emulate variable1 changing every 500 ms
        setInterval(() => {
            v1 += 1;
            v2 = !v2;
        }, 250);


        var v3 = "";
        addressSpace.addVariable({
            componentOf: sampleDir,
            nodeId: "ns=2;s=v3",
            browseName: "v3",
            dataType: "String",
            value: {
                get: () => new opcua.Variant({dataType: opcua.DataType.String, value: v3})
            }
        });

        var v4 = 1;
        addressSpace.addVariable({
            componentOf: sampleDir,
            nodeId: "ns=2;s=v4",
            browseName: "v4",
            dataType: "Double",
            value: {
                get: () => new opcua.Variant({dataType: opcua.DataType.Double, value: v4})
            }
        });
        // emulate variable1 changing every 500 ms
        var slowCounter = 1;
        setInterval(() => {
            slowCounter += 1;
            v3 = "Hello world times " + slowCounter;
            v4 = Math.sin((slowCounter % 360) * Math.PI / 180.0);
        }, 1000);
    }

    construct_my_address_space(server);
    server.start(() => {
        console.log("Server is now listening on these endpoints... ( press CTRL+C to stop)");
        server.endpoints[0].endpointDescriptions().forEach(endpoint => {
            console.log(endpoint.endpointUrl, endpoint.securityMode.toString(), endpoint.securityPolicyUri.toString());
        });
    });
}

server.initialize(post_initialize);
