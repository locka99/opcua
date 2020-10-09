/*global require,setInterval,console */
const opcua = require("node-opcua");

// Let's create an instance of OPCUAServer
const server = new opcua.OPCUAServer({
    securityPolicies: [opcua.SecurityPolicy.None, opcua.SecurityPolicy.Basic128Rsa15, opcua.SecurityPolicy.Basic256, opcua.SecurityPolicy.Basic256Sha256, opcua.SecurityPolicy.Aes128_Sha256_RsaOaep],
    securityModes: [opcua.MessageSecurityMode.None, opcua.MessageSecurityMode.Sign, opcua.MessageSecurityMode.SignAndEncrypt],
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

        const addressSpace = server.engine.addressSpace;

        const ns = addressSpace.registerNamespace("uri:my_sample");

        // declare a new object
        const sampleDir = ns.addObject({
            organizedBy: addressSpace.rootFolder.objects,
            browseName: "Sample"
        });

        // int, bool, string, double

        let v1 = 100;
        ns.addVariable({
            componentOf: sampleDir,
            nodeId: "ns=2;s=v1",
            browseName: "v1",
            dataType: "Int32",
            value: {
                get: () => new opcua.Variant({dataType: opcua.DataType.Int32, value: v1})
            }
        });


        let v2 = false;
        ns.addVariable({
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


        let v3 = "";
        ns.addVariable({
            componentOf: sampleDir,
            nodeId: "ns=2;s=v3",
            browseName: "v3",
            dataType: "String",
            value: {
                get: () => new opcua.Variant({dataType: opcua.DataType.String, value: v3})
            }
        });

        let v4 = 1;
        ns.addVariable({
            componentOf: sampleDir,
            nodeId: "ns=2;s=v4",
            browseName: "v4",
            dataType: "Double",
            value: {
                get: () => new opcua.Variant({dataType: opcua.DataType.Double, value: v4})
            }
        });
        // emulate variable1 changing every 500 ms
        let slowCounter = 1;
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
