TODO

This is an OPC UA recorder and playback tool.

Use it to subscribe to changes on variables from another OPC UA server into a file, and then play them back from file as 
your own server. This may be useful if you are trying to simulate a live OPC UA server.

opcua-recorder --record
opcua-recorder --playback --loop

Recording is configured from a config file recorder.conf which defines the server you wish to connect to, 
the pattern of variables you wish to record and the output file.

Playback is configured from a config file playback.conf which defines the server you wish to pose as and the input
file you wish to playback.