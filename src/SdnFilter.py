from KnowledgeBase import KnowledgeBase, TenantKnowledgeBase
from osdn_exceptions import JsonRpcInvalidParams
from utils import get_logger

_log = get_logger(__name__)


class SdnFilterError(Exception):
    pass


class SdnFilter:
    _token2tenant = dict()

    def add_experiment(self, token: str, tenant_id: str):
        self._token2tenant[token] = tenant_id

    def remove_experiment(self, token: str) -> str:
        return self._token2tenant.pop(token)

    def token_to_tenant(self, token: str) -> str:
        return self._token2tenant.get(token, None)

    def validate_request(self, token, method, args) -> bool:
        return False

    def filter_response(self, response, method):
        return response


class WhitelistFilter(SdnFilter):
    def __init__(self, whitelist=list()) -> None:
        super().__init__()
        self._whitelist = whitelist
        _log.debug("Created WhitelistFilter with whitelist: %s" % whitelist)

    def filter_response(self, response, method):
        return response

    def validate_request(self, token, method, args) -> bool:
        _log.debug("requested method: %s" % method)
        return (method is not None) and (method in self._whitelist)


class OpenSdnCoreFilter(SdnFilter):
    """
    This class implements filters to handle JSON-RPC requests of the OpenSDNcore Northbound API
    """

    def __init__(self, knowlagebase: KnowledgeBase, allowed_methods=None) -> None:
        super().__init__()
        if allowed_methods:
            self._allowed_methods = allowed_methods
        else:
            self._allowed_methods = ["help", "list.methods",
                                     "ofc.send.get_config", "ofc.list.channels",
                                     "ofc.send.flow_mod", "ofc.send.barrier",
                                     "ofc.send.multipart.flow", "ofc.send.multipart.port_stats",
                                     "ofc.send.multipart.port_description"]
        self._forbidden_methods = ["ofc.send.role_request"]
        if not knowlagebase:
            self._knowlagebase = KnowledgeBase()
            self._knowlagebase.add_tenant("2b5c4fc95268456985ad2254253f49d5", TenantKnowledgeBase([10]))
            self._knowlagebase.add_tenant("123invalid456", TenantKnowledgeBase(flowtables=[300]))
        else:
            self._knowlagebase = knowlagebase

    def filter_response(self, response: dict, method):
        if method == "list.methods":
            response["result"] = [v for v in response.get("result", list()) if v in self._allowed_methods]
            return response
        return super().filter_response(response, method)

    def validate_request(self, token, method, args) -> bool:
        """
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
        :param token:
        :param method:
        :param args:
        :return:
        """

        allowed_methods_wo_check = ["help", "list.methods",
                                    "ofc.send.get_config", "ofc.list.channels"]

        _log.debug("typeof args: %s" % type(args))

        if method in self._allowed_methods:
            tenant_id = self.token_to_tenant(token)
            if not tenant_id:
                _log.error("can't find tenant_id for token %s" % token)
                return False

            if method in allowed_methods_wo_check:
                return True

            if method == "ofc.send.flow_mod":
                return self._validate_flow_mod(tenant_id, args)
            elif method == "ofc.send.barrier":
                """
                send barrier message, used to ensure message dependencies have been met or wants to 
                receive notifications for completed operations. The switch will continue to execute new 
                commands only if all the messages before the barrier have been processed
                """
                pass
            elif method == "ofc.send.role_request":
                """used to query or change the role of controller"""
                #  forbidden
                return False
            elif method == "ofc.send.multipart.flow":
                """get statistic information about individual flow entries"""
                return self._validate_multipart_flow(tenant_id, args.get("ofp_multipart_flow", dict()))
                pass
            elif method == "ofc.send.multipart.port_stats":
                """get aggregate statistic information about ports"""
                return True
            elif method == "ofc.send.multipart.port_description":
                """get a description of all the ports in the system that support OpenFlow"""
                return True

            _log.warn("method filtering %s not implemented" % method)
            return False

        _log.warn("method %s not allowed" % method)
        return False

    def _validate_match_class_openflow_basic(self, tenant_id: str, match: dict) -> bool:
        """
        validate openflow_basic match_class object
        (http://docs.softfire.eu/opensdncore-nb-api/#ofp_oxm)
        :param tenant_id:
        :param match: ofp_oxm dict
        :return:
        """
        field = match["field"]
        value = match["value"]
        mask = match["mask"]
        _log.debug("all openflow_basic types are allowed (field: %s value: %s)" % (field, value))
        return True

    def _validate_ofp_oxm(self, tenant_id: str, match: dict) -> bool:
        match_class = match.get("match_class", "")
        if match_class == "openflow_basic":
            _log.debug("found match_class: %s" % match_class)
            if not self._validate_match_class_openflow_basic(tenant_id, match):
                raise SdnFilterError("ofp_match not allowed")
        else:
            raise SdnFilterError("only 'openflow_basic' match_class is allowed")
        return False

    def _validate_action(self, action: str, data: dict, tenant_id) -> bool:
        """
{
   "ofp_actions":{
      "write_actions":[
         {
            "set_field":{
               "ofp_oxm":{
                  "match_class":"openflow_basic",
                  "field":"ipv4_src",
                  "value":"11.0.0.1"
               }
            }
         },
         {
            "set_field":{
               "ofp_oxm":{
                  "match_class":"openflow_basic",
                  "field":"ipv4_dst",
                  "value":"11.0.0.2"
               }
            }
         },
         {
            "output":{
               "port_no":"0x02"
            }
         }
      ]
   }
}
        :param action:
        :param data:
        :return:
        """
        unhandled_actions = ["set_queue", "set_nw_ttl", "push_vlan", "push_pbb", "push_mpls", "experimenter",
                             "copy_ttl_out", "copy_ttl_in", "dec_nw_ttl", "pop_vlan"]
        allowed_actions_wo_check = ["group", "set_mpls_ttl", "pop_mpls", "dec_mpls_ttl", "pop_pbb"]

        if action in allowed_actions_wo_check:
            return True
        if action in unhandled_actions:
            raise SdnFilterError("action %s unhandled -> Forbidden" % action)

        if action == "output":
            port_no = data["port_no"]  # a 32-bit number between [0, 0xffffff00] or one of OFPP enumeration
            _log.warn("!! output to port %s unfiltered" % port_no)
        elif action == "set_field":
            # the field to set described by a single oxm
            return self._validate_ofp_oxm(tenant_id, data)
        elif action == "dummy":
            pass

        return False

    def _validate_instruction(self, tenant_id: str, instruction: str, data: dict) -> bool:
        """
        Example:
        "goto_table": {
                        "table_id": "0x03"
                    }
        :param tenant_id:
        :param instruction:
        :param data:
        :return:
        """
        instructions_allowed_wo_check = ["write_metadata", "meter", "clear_actions"]
        unhandled_instructions = ["experimenter"]

        if instruction in instructions_allowed_wo_check:
            return True

        if instruction in unhandled_instructions:
            raise SdnFilterError("instruction %s unhandled -> Forbidden" % instruction)

        if instruction == "goto_table":
            table_id = data["table_id"]
            return self._knowlagebase.check_flowtable(tenant_id, table_id)

        if instruction in ["apply_actions", "write_actions"]:
            if isinstance(data, list):
                for dataitem in data:
                    for action, v in dataitem.values():
                        if not self._validate_action(action, v, tenant_id):
                            raise SdnFilterError("action %s inside instruction %s not allowed" % (action, instruction))
                    _log.debug("all actions for inst:%s validated" % instruction)
                    return True

        return False

    def _validate_flow_mod(self, tenant_id: str, args: dict) -> bool:
        """
        Example:
        args: {
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
        :param tenant_id:
        :param args:
        :return:
        """
        if not isinstance(args, dict):
            raise SdnFilterError("arguments need to be a dictionary")

        valid_commands_OFPFC = ["add", "modify", "modify_strict", "delete", "delete_strict"]
        valid_flags_OFPFF = ["send_flow_rem", "check_overlap", "reset_counts", "no_pkt_counts", "no_byt_counts"]
        try:
            ofp_flow_mod = args["ofp_flow_mod"]
            target_table = ofp_flow_mod["table_id"]  # extract flow-table to which the flow should be written
            if self._knowlagebase.check_flowtable(tenant_id, target_table):
                command = ofp_flow_mod["command"]
                if command not in valid_commands_OFPFC:
                    return False

                flags = ofp_flow_mod.get("flags", None)
                # flags are not mandatory
                if flags:
                    for flag in flags:
                        if flag not in valid_flags_OFPFF:
                            return False

                ofp_match = ofp_flow_mod.get("ofp_match", None)
                if isinstance(ofp_match, dict):
                    #  ofp_oxm structure
                    self._validate_ofp_oxm(tenant_id, ofp_match)

                ofp_instructions = ofp_flow_mod["ofp_instructions"]
                if isinstance(ofp_instructions, dict):
                    for inst, v in ofp_instructions.items():
                        if not self._validate_instruction(tenant_id, inst, v):
                            raise SdnFilterError("ofp_instruction not allowed")

            else:
                _log.debug("flow_table(%d) is not owned by tenant %s" % (target_table, tenant_id))
                return False

        except KeyError as e:
            _log.error(e)
            raise SdnFilterError("Request parameter error: %s" % e)
        except Exception as e:
            _log.error(e)

        return False

    def _validate_multipart_flow(self, tenant_id: str, ofp_multipart_flow: dict) -> bool:
        target_table = ofp_multipart_flow["table_id"]  # extract flow-table to which the flow should be written
        if self._knowlagebase.check_flowtable(tenant_id, target_table):
            return True
        _log.debug("flow-table %s not allowed for tenant %s" % (target_table, tenant_id))
        raise JsonRpcInvalidParams("flow-table %s not allowed" % target_table)
        return False
