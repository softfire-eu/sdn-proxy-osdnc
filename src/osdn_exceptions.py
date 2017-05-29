class JsonRpcError(Exception):
    '''
    Exception that is used to encode JSON-RPC error codes
    
    code	message	meaning
    -32700	Parse error	        Invalid JSON was received by the server. An error occurred on the server while parsing the JSON text.
    -32600	Invalid Request	    The JSON sent is not a valid Request object.
    -32601	Method not found	The method does not exist / is not available.
    -32602	Invalid params	    Invalid method parameter(s).
    -32603	Internal error	    Internal JSON-RPC error.
    -32000 
    to      Server error	Reserved for implementation-defined server-errors. 
    -32099
    '''
    def __init__(self, message="Internal error", code=-32603, id=None, jsonrpcversion=2):
        self.message = message
        self.errorcode=code
        self.id=id;
        self.version=jsonrpcversion

    @property
    def toJsonRpcMessage(self) -> dict:
        return dict(id=self.id, error=dict(message=self.message, code=self.errorcode), jsonrpc=self.version)

class JsonRpcInternalError(JsonRpcError):
    pass

class JsonRpcParseError(JsonRpcError):
    def __init__(self, message, id=None, jsonrpcversion=2):
        super().__init__(message, -32700, id, jsonrpcversion)
        self.message = "Parse error: %s"%message

class JsonRpcInvalidRequest(JsonRpcError):
    def __init__(self, message, id=None, jsonrpcversion=2):
        super().__init__(message, -32600, id, jsonrpcversion)
        self.message = "Invalid Request: %s" % message

class JsonRpcMethodNotFound(JsonRpcError):
    def __init__(self, message, id=None, jsonrpcversion=2):
        super().__init__(message, -32601, id, jsonrpcversion)
        self.message = "Method not found: %s" % message

class JsonRpcInvalidParams(JsonRpcError):
    def __init__(self, message="Internal error", code=-32603, id=None, jsonrpcversion=2):
        super().__init__(message, code, id, jsonrpcversion)
        self.message = "Invalid params: %s" % message

class JsonRpcServerError(JsonRpcError):
    def __init__(self, message="Server error", code=-32000, id=None, jsonrpcversion=2):
        super().__init__(message, code, id, jsonrpcversion)