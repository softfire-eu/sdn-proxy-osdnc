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


class TenantKnowlageBase(object):
    def __init__(self) -> None:
        super().__init__()
        self._allowed_flowtables = []
        self._mac_addresses = []

    def check_flowtable(self, flowtable) -> bool:
        return flowtable in self._allowed_flowtables

    def check_mac_address(self, mac_address) -> bool:
        return mac_address in self._mac_addresses


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

    def __init__(self, allowed_methods=[]) -> None:
        super().__init__()
        self._allowed_methods = allowed_methods
        self._knowlagebase = TenantKnowlageBase()

    def filterResponse(self, response):
        return super().filterResponse(response)

    def validateRequest(self, token, method, args) -> bool:
        return super().validateRequest(token, method, args)
