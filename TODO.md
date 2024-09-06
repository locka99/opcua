# TODO

This is a pending rewrite of the OPC-UA stack, following up on the rewrite of the client to be async all the way through.

The following is a list of tasks, with progress indicated where relevant.

 - Rewrite the server to be async, and a great deal more flexible, making it possible to create _really_ advanced servers using this SDK.
   - **~100%** done with the initial scope, barring any bugs or details that need fixing.
     - Some features are left out:
     - Diagnostics, both as diagnosticsInfo from services, and general session diagnostics. There's a skeleton for this in the DiagnosticsNodeManager.
     - Events are _implemented_ but incredibly cumbersome to write, so there is nothing fancy implemented for them. See below.
     - Audit events are taken out due to the above.
     - The web server is removed. Likely forever, a better solution is to use the `metrics` library to hook into the rust metrics ecosystem.
     - A smattering of TODO's, most are somehow blocked by other tasks.
 - Merge most recent PRs on the main repo, especially the one migrating away from OpenSSL.
 - Split the library into parts again.
   - Initially into types, client, core, and server.
   - This is needed for other features.
 - Write a codegen/macro library. Initially this should just replace all the JS codegen, later on it will do _more_.
   - It would be best if this could be written in such a way that it can either be used as a core for a macro library, or as a standalone build.rs codegen module.
 - Implement sophisticated event support, using a macro to create event types.
 - Investigate decoding. There are several things that would be interesting to do here.
   - Capture request-id/request-handle for error reporting during decoding. This will allow us to fatally fail much less often, but will require major changes to codegen.
   - See if there is a way to avoid needing to pass the ID when decoding ExtensionObjects. This info should be available, either in the object itself or as part of the type being decoded.
 - Flesh out the server and client SDK with tooling for ease if use.
   - I had an idea of a "request builder" framework for the client SDK, which might be really useful.
   - The server should be possible to set up in such a way that it is no harder to use than before. A specialized node manager would be ideal for this.
   - There are probably lots of neat logic we can add as utility methods that make it easier to implement node managers.
 - Go through the standard and implement _more_ of the core stuff. Diagnostics, server management methods, etc.
 - Implement a better framework for security checks. (?)
 - Write a sophisticated server example with a persistent store. This would be a great way to verify the flexibility of the server.
 - Write some "bad ideas" servers, it would be nice to showcase how flexible this is.
 - Look into using non-send locks, to eliminate a source of deadlocks.
