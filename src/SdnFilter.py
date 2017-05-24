
class SdnFilter:
    def validateRequest(self, token, method, args) -> bool:
        return False

    def filterResponse(self, response):
        return response

class WhitelistFilter(SdnFilter):
    _whitelist = []

    def __init__(self, whitelist=[]) -> None:
        super().__init__()
        self._whitelist = whitelist

    def validateRequest(self, token, method, args) -> bool:
        
        return method is not None and method in self._whitelist

class OpenSdnCoreFilter(SdnFilter):
    '''
    This class implements filters to handle JSON-RPC requests of the OpenSDNcore Northbound API 
    '''

    def filterResponse(self, response):
        return super().filterResponse(response)

