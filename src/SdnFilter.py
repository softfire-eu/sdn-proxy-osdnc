from utils import get_logger

_log = get_logger(__name__)


class SdnFilter:
    def validateRequest(self, token, method, args) -> bool:
        return False

    def filterResponse(self, response):
        return response


class WhitelistFilter(SdnFilter):
    def __init__(self, whitelist=list()) -> None:
        super().__init__()
        self._whitelist = whitelist
        _log.debug("Created WhitelistFilter with whitelist: %s" % whitelist)

    def filterResponse(self, response):
        return response

    def validateRequest(self, token, method, args) -> bool:
        _log.debug("requested method: %s" % method)
        return (method is not None) and (method in self._whitelist)


class OpenSdnCoreFilter(SdnFilter):
    """
    This class implements filters to handle JSON-RPC requests of the OpenSDNcore Northbound API
    Example command:
    {
      "jsonrpc": "2.0",
      "id": 1,
      "method": "ofc.send.flow_mod",
      "params": {
        "dpid": "0x0000000000000001",
        "ofp_flow_mod": {
          "command": "add",
          "flags": [
            "reset_counts",
            "send_flow_rem"
          ],
          "idle_timeout": 0,
          "ofp_instructions": {
            "goto_table": {
              "table_id": "0x03"
            }
          },
          "ofp_match": [
            {
              "match_class": "openflow_basic",
              "field": "ipv4_dst",
              "value": "192.168.100.0",
              "mask": "255.255.255.0"
            }
          ],
          "priority": 996,
          "table_id": "0x00"
        }
      }
    }
    """

    def filterResponse(self, response):
        return super().filterResponse(response)

    def validateRequest(self, token, method, args) -> bool:
        return super().validateRequest(token, method, args)
