## Server Structure

The server is added as a compiled module which can be started as a background service by _ORIGO_ commands. The `pid.json` keeps track of the process identifier once the service has been started. The server service starts an HTTPS server configured to run TLS1.3 with a specific cipher suite and responds https requests with a static response. When _ORIGO_ is executed locally, the server must be started.



