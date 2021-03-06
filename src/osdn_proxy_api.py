#!/usr/bin/env python
import configparser
import datetime
import json
import os

import bottle
import requests
from bottle import post, get, delete, route
from bottle import request, response
from ofsctl import ofsctl, ofs_json, db

import utils
from KnowledgeBase import KnowledgeBase, TenantKnowledgeBase
from SdnFilter import SdnFilter, OpenSdnCoreFilter
from osdn_exceptions import JsonRpcParseError, JsonRpcInvalidRequest, JsonRpcError, JsonRpcServerError, \
    JsonRpcInternalError
from utils import get_logger, get_config

logger = get_logger(__name__)

_experiments = dict()
_auth_secret = "secret"
_api_endpoint = "http://127.0.0.1:8001/"
_osdnc_api = "http://192.168.41.153:10010/"
_opensdncore_dpid = "0000000000000001"
_SdnFilter = SdnFilter()
_number_of_tables_per_tenant = 3
_knowledgebase = KnowledgeBase()


def check_auth_header(headers: dict) -> bool:
    if "Auth-Secret" in headers.keys():
        auth_secret = headers.get("Auth-Secret")
        logger.debug("'Auth-Secret' header present! value: %s" % auth_secret)
        if auth_secret == _auth_secret:
            return True
    return False


def get_user_flowtables(tenant_id):
    ofsdb = ofsctl.get_db()
    if ofsdb.db_type == "mysql":
        logger.debug("querying ofsdb @%s" % ofsdb.mysql_config.get("host"))
    else:
        logger.debug("reading ofsDB from %s" % ofsdb.db_file)
    start_ft = int(ofsdb.get_of_start_table_from_tenant(tenant_id)[0][0])
    logger.debug("done!")
    return list(range(start_ft, start_ft + _number_of_tables_per_tenant))


def get_next_os_table_offset(max_of_table_ofs):
    if max_of_table_ofs + _number_of_tables_per_tenant < (254 - _number_of_tables_per_tenant):
        return max_of_table_ofs + _number_of_tables_per_tenant
    else:
        logger.error("number of flow tables exhaust!")


def get_next_os_table_offset_from_list(table_list: list):
    table_list.extend(range(0, 8))
    table_list.sort()
    if 250 not in table_list:
        table_list.append(250)
    last = None
    for value in table_list:
        if last and value > last:
            if value - last >= 2 * _number_of_tables_per_tenant:
                return last + _number_of_tables_per_tenant
        last = value


def find_next_os_table_offset(list_of_of_table_ofs):
    raise Exception("function unimplemented")


@post("/PrepareTenant")
def proxy_prepare_tenant():
    """
 >{
     "tenant_id": "fed0b52c7e034d5785880613e78d4411"
 }
 <{
   "flow-table-offset": 10
  }
    :return:
    """
    if not check_auth_header(request.headers):
        raise bottle.HTTPError(403, "Auth-Secret error!")
    else:
        # parse input data
        try:
            logger.debug("proxy_prepare_tenant: JSON: %s" % request.json)
            data = request.json
            tenant_id = data.get("tenant_id")
            logger.debug("received tenant_id: %s" % tenant_id)
            if not tenant_id:
                return bottle.HTTPError(500, "tenant id missing")

            ofsdb = ofsctl.get_db()
            tenants = ofsdb.list_tenants()
            table_ofs_list = list()
            max_of_table = 0
            flow_table_offset = None
            for tenant, flow in tenants:
                logger.debug("proxy_prepare_tenant: OFSdb(tenant: %s of_table_ofs: %s)" % (tenant, flow))
                flow = int(flow)
                table_ofs_list.append(flow)
                if max_of_table < flow:
                    max_of_table = flow
                if tenant == tenant_id:
                    logger.info("proxy_prepare_tenant: tenant (%s) already prepared in OFSdb" % tenant_id)
                    flow_table_offset = flow
            logger.debug("proxy_prepare_tenant: max_flowt: %d" % (max_of_table))
            if flow_table_offset is None:
                # create new entry
                next_os_table_offset = get_next_os_table_offset_from_list(table_ofs_list)
                if next_os_table_offset:
                    logger.info(
                        "proxy_prepare_tenant: creating a new tenant in ofsDB with ofs: %d" % next_os_table_offset)
                    ofsdb.add_tenant(tenant_id, next_os_table_offset)
                    flow_table_offset = int(ofsdb.get_of_start_table_from_tenant(tenant_id)[0][0])
                else:
                    logger.error("proxy_prepare_tenant: cant get next free flowtable...")
                    return bottle.HTTPError(500, "can't get next free flow table")

        except Exception as e:
            logger.error(e)
            raise Exception("invalid input data")
        logger.debug("proxy_prepare_tenant: flow-table-offset: %s" % flow_table_offset)
        response.headers['Content-Type'] = 'application/json'
        response.headers['Cache-Control'] = 'no-cache'
        return json.dumps({"flow-table-offset": flow_table_offset})


@post('/SDNproxySetup')
def proxy_creation_handler():
    """Handles experiment/proxy creation
      request:
      {
        "experiment_id": "a5cfaf1e81f35fde41bef54e35772f2b",
        "tenant_id": "fed0b52c7e034d5785880613e78d4411"
      }
      response:ofsdb.get_of_start_table_from_tenant(tenant_id)
      {
        "endpoint_url": "http:/foo.bar",
        "user-flow-tables": [10,11,12]
      }
    """
    if not check_auth_header(request.headers):
        raise bottle.HTTPError(403, "Auth-Secret error!")

    try:
        # parse input data
        try:
            data = request.json
            logger.debug("SDNproxySetup: JSON: %s" % request.json)
        except Exception as e:
            logger.error(e)
            raise ValueError(e)

        if data is None:
            print("Cant read json request")
            raise ValueError

        experiment_id = data['experiment_id']
        tenant_id = data["tenant_id"]

        # check for existence
        if experiment_id in _experiments:
            logger.error("SDNproxySetup: duplicate experiment %s" % experiment_id)
            response.status = 500
            return "Duplicate experiment!"

        user_flowtables = get_user_flowtables(tenant_id)
        logger.debug("add to _experiments")
        _experiments[experiment_id] = {"tenant": tenant_id,
                                       "flow_tables": user_flowtables,
                                       "timestamp": datetime.datetime.now().isoformat()
                                       }
        logger.debug("add to SdnFilter")
        _SdnFilter.add_experiment(experiment_id, tenant_id)
        logger.debug("add to KnowledgeBase")
        _knowledgebase.add_tenant(tenant_id, TenantKnowledgeBase(flowtables=user_flowtables))
        utils.store_experiments(_experiments)
        # _SdnFilter.token_to_tenant()

        response.headers['Content-Type'] = 'application/json'
        response.headers['Cache-Control'] = 'no-cache'
        return json.dumps(
            {"user-flow-tables": user_flowtables, "endpoint_url": _api_endpoint})

    except Exception as e:
        logger.error("SDNproxySetup failed: %s" % e)
        response.status = 500
        raise bottle.HTTPError(500, exception=e)
        # return e


@get('/ofsctl_list_tenants')
@get('/ofsctl_del_tenant/<delid>')
@delete('/RemoveTenant/<delid>')
def handle_ofsctl_list_tenants(delid=None):
    if not check_auth_header(request.headers):
        raise bottle.HTTPError(403, "Auth-Secret error!")
    ofsdb = ofsctl.get_db()
    dellist = []
    if delid:
        for ex, v in _experiments.items():
            tid = v.get("tenant", None)
            if tid == delid:
                dellist.append(ex)
            if len(dellist) > 0:
                for exp in dellist:
                    delete_experiment(exp)
        logger.info("deleting tenant %d from ofsDB..")
        flowlist = get_user_flowtables(delid)
        cport = db.ofs_db.get_console_port_from_br(ofsdb, _opensdncore_dpid)
        if len(flowlist) > 0:
            for flow_table_id in flowlist:
                ofs_json.del_flow_table(_opensdncore_dpid, cport, flow_table_id)
        ofsdb.del_tenant(delid)
    logger.info("listing tenants from ofsDB")
    tenants = ofsdb.list_tenants()
    response.headers['Content-Type'] = 'application/json'
    response.headers['Cache-Control'] = 'no-cache'
    res = dict()
    for k, v in tenants:
        res[k] = v
    return json.dumps(res)


@get('/ofsctl_listbr')
def handle_ofsctl_list_br():
    if not check_auth_header(request.headers):
        raise bottle.HTTPError(403, "Auth-Secret error!")
    response.headers['Content-Type'] = 'application/json'
    response.headers['Cache-Control'] = 'no-cache'
    ofsdb = ofsctl.get_db()
    return json.dumps(ofsdb.list(None))


@get('/SDNproxy')
def proxy_listing_handler():
    """Handles name listing"""
    response.headers['Content-Type'] = 'application/json'
    response.headers['Cache-Control'] = 'no-cache'
    if check_auth_header(request.headers):
        logger.debug("Listing SDNproxies with full details!")
        return json.dumps(_experiments)
    else:
        logger.debug("Auth header missing or invalid, listing SDN proxies with reduced details")
        res = dict()
        for ex, v in _experiments.items():
            exid = "%s...%s" % (ex[:3], ex[len(ex) - 3:])
            tid = v["tenant"]
            tid = "%s...%s" % (tid[:3], tid[len(tid) - 3:])
            res[exid] = dict(tenant=tid, flow_tables=v.get("flow_tables"), timestamp=v.get("timestamp"))
        return json.dumps(res)


@get('/SDNproxy/<token>')
def proxy_details_handler(token):
    """Handles experiment details"""

    if check_auth_header(request.headers):
        if token in _experiments:
            response.headers['Content-Type'] = 'application/json'
            response.headers['Cache-Control'] = 'no-cache'
            return json.dumps(_experiments[token])
        else:
            raise bottle.HTTPError(404)
    else:
        raise bottle.HTTPError(403, "Auth-Secret error!")


@delete('/SDNproxy/<token>')
def delete_handler(token):
    """delete the mapping between experiment-token and tenant id
    :returns  200 but no body
    """
    if not check_auth_header(request.headers):
        raise bottle.HTTPError(403, "Auth-Secret error!")
    else:
        status, msg = delete_experiment(token)
        logger.debug(msg)
        response.headers['Content-Type'] = 'application/json'
        return json.dumps({"msg": msg})


def delete_experiment(experimentid):
    if _experiments.pop(experimentid, None) is None:
        status = 404
        msg = "Experiment not found!"
    else:
        status = 200
        msg = "Experiment successfully deleted!"
        utils.store_experiments(_experiments)
    return status, msg


# ######### static files

@route('/', method="GET")
@route('/index.html', method="GET")
def handle_index():
    return bottle.static_file('index.html', root=os.path.join(os.getcwd(), 'static'))


@route('/favicon.ico', method="GET")
def handle_favicon():
    return bottle.static_file('favicon.ico', root=os.path.join(os.getcwd(), 'static'))


# ######### end static files

# ######### OpenSDNCore API proxy

@post('/api')
@post('/api/<urltoken>')
def do_proxy_jsonrpc(urltoken=None):
    """

    :param urltoken:
    :return:
    """

    token = request.headers.get('API-Token', urltoken)

    try:
        try:
            dataj = json.loads(request.body.read().decode("utf-8"))
        except Exception as e:
            raise JsonRpcParseError(str(e))

        if token is None:
            raise JsonRpcServerError("Token missing")
        if isinstance(dataj, list):
            logger.debug("Request is a list")
            res = []
            for rj in dataj:
                try:
                    resdata = do_handle_jsonrpc_request(rj, token)
                    if resdata:
                        res.append(resdata)
                except JsonRpcError as err:
                    res.append(err.toJsonRpcMessage)
            response.headers['Content-Type'] = 'application/json'
            return res
        else:
            return do_handle_jsonrpc_request(dataj, token)
    except JsonRpcError as err:
        response.headers['Content-Type'] = 'application/json'
        return err.toJsonRpcMessage
    except KeyError as ke:
        logger.error("%s missing from json-rpc request" % ke.args[0])
        response.headers['Content-Type'] = 'application/json'
        return JsonRpcError(message="%s missing from json-rpc request" % (ke.args[0])).toJsonRpcMessage
    except Exception as e:
        logger.error(e)
        response.headers['Content-Type'] = 'application/json'
        return JsonRpcError(message="Error Handling request. Exception(%s): %s" % (type(e), e.args[0])).toJsonRpcMessage


def do_handle_jsonrpc_request(jsonrcp, token) -> dict:
    """
    Handle a single JSON-RPC request object
    :param jsonrcp: JSON-RCP request dictionary/object
    :param token:   Security Token
    :return:        JSON-RPC response object
    :raises JsonRpcError: in case of error
    """

    if not isinstance(jsonrcp, dict):
        logger.error("request is not a dict()!!")
        return dict()

    try:
        request_id = jsonrcp.get('id')
    except AttributeError as ate:
        logger.debug("JSON request ID missing -> Notification not supported")
        return dict()
        # raise JsonRpcInvalidRequest(str(ate))

    do_validate_jsonrpc_request(token, jsonrcp, request_id)

    r = requests.post(_osdnc_api, data=bottle.request.body, headers={'Content-Type': 'application/json-rpc'})
    logger.debug("Result status: %d " % r.status_code)
    if r.headers.get('Content-Type') and r.headers['Content-Type'] == "application/json":
        try:
            resj = r.json()
            logger.debug("Result from OpenSDNcore: %s" % resj)
        except ValueError as e:
            logger.error("Error reading response json: %s" % e)
            raise JsonRpcServerError("error parsing the response from OpenSDNcore!", id=request_id)

        _SdnFilter.filter_response(resj, jsonrcp.get("method"))
        response.status = r.status_code
        return resj
    else:
        logger.debug("OpenSDNcore returned no json! headers: %s" % r.headers)
        raise JsonRpcInternalError("Invalid response from upstream server", id=request_id)


def do_validate_jsonrpc_request(token: str, rpcdata: dict, id) -> None:
    """
    Check if a JSON-RPC request is valid and allowed using an SdnFilter instance.
    :param token:   Security Token
    :param rpcdata: JSON-RPC request object
    :param id:      JSON-RPC request id
    :return:        True / False
    """
    if token is None:
        logger.info("Token not found in request!")
        raise JsonRpcServerError("API-Token missing", code=-32043, id=id)

    experimenter = _experiments.get(token)
    if experimenter is None:
        logger.info("Invalid Token %s" % token)
        raise JsonRpcServerError("Invalid API-Token", code=-32043, id=id)

    logger.debug("Request: %s" % rpcdata)
    try:
        method = rpcdata.get("method")
    except Exception as e:
        logger.error("method not found in request")
        raise JsonRpcInvalidRequest(str(e))

    logger.debug("Method: %s" % method)
    logger.debug("using SDNFilter %s to validate request" % type(_SdnFilter))

    if not _SdnFilter.validate_request(token, method, rpcdata.get("params", [])):
        raise JsonRpcServerError("Method not Allowed", code=-32043, id=id)


def start(config: configparser.ConfigParser):
    global _SdnFilter, _auth_secret, _api_endpoint, _osdnc_api, _experiments
    logger.info("starting up")

    _auth_secret = get_config("sdn", "sdn-manager-auth-secret", default="not_so_secret_token", config=config)
    _api_endpoint = get_config("sdn", "local-api-endpoint", default="http://127.0.0.1:8001/", config=config)
    _osdnc_api = get_config("sdn", "opensdncore-api-url", default="http://192.168.41.153:10010/", config=config)

    _experiments = utils.load_experiments(config)

    try:
        utils.store_experiments(_experiments, config)  # check if the file is writable
    except Exception as e:
        logger.error("state file not writable!!: %s" % e)
        exit(0)

    _SdnFilter = OpenSdnCoreFilter(_knowledgebase)
    for k, v in _experiments.items():
        logger.debug("adding experiment %s to SdnFilter.." % k)
        tenant = v["tenant"]
        _SdnFilter.add_experiment(k, tenant)
        try:
            _knowledgebase.add_tenant(tenant, TenantKnowledgeBase(get_user_flowtables(tenant)))
        except Exception as e:
            logger.warn("adding tenant '%s' to knowledgebase failed: %s" % (tenant, e))
            pass
    bottle.run(host='0.0.0.0', port=8001, reloader=True)
