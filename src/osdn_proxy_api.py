#!/usr/bin/env python

import json
import os

import bottle
import requests
from bottle import post, get, delete, route
from bottle import request, response

from SdnFilter import SdnFilter, WhitelistFilter
from osdn_exceptions import JsonRpcParseError, JsonRpcInvalidRequest, JsonRpcError, JsonRpcServerError, \
    JsonRpcInternalError
from utils import get_logger

logger = get_logger(__name__)

_experiments = dict()
_auth_secret = "90d82936f887a871df8cc82c1518a43e"
_api_endpoint = "http://127.0.0.1:8001/"
_osdnc_api = "http://192.168.41.153:10010/"
_mySdnFilter = SdnFilter()


def check_auth_header(headers):
    if "Auth-Secret" in headers.keys():
        auth_secret = headers.get("Auth-Secret")
        logger.debug("'Auth-Secret' header present! value: %s" % auth_secret)
        if auth_secret == _auth_secret:
            return True
    return False


def get_user_flowtables(tenant_id):
    return list(range(11, 21))


@post('/SDNproxySetup')
def proxy_creation_handler():
    """Handles experiment/proxy creation
      request:
      {
        "experiment_id": "a5cfaf1e81f35fde41bef54e35772f2b",
        "tenant_id": "fed0b52c7e034d5785880613e78d4411"
      }
      response:
      {
        "endpoint_url": "http:/foo.bar",
        "user-flow-tables": [10,11,12,13,14,15]
      }
    """
    try:
        # parse input data
        try:
            data = request.json
            logger.debug("JSON: %s" % request.json)
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
            response.status = 500
            return "Duplicate experiment!"

        _experiments[experiment_id] = {"tenant": tenant_id, "flow_tables": get_user_flowtables(experiment_id)}

        response.headers['Content-Type'] = 'application/json'
        response.headers['Cache-Control'] = 'no-cache'
        return json.dumps(
            {"user-flow-tables": _experiments[experiment_id]["flow_tables"], "endpoint_url": _api_endpoint})

    except:
        response.status = 500


@get('/SDNproxy')
def proxy_listing_handler():
    """Handles name listing"""
    response.headers['Content-Type'] = 'application/json'
    response.headers['Cache-Control'] = 'no-cache'
    # return json.dumps(list(request.headers.items()))
    return json.dumps(_experiments)


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
    if check_auth_header(request.headers):
        if _experiments.pop(token, None) is None:
            response.status = 404
            msg = "Experiment not found!"
        else:
            response.status = 200
            msg = "Experiment successfully deleted!"
        logger.debug(msg)
        response.headers['Content-Type'] = 'application/json'
        return json.dumps({"msg": msg})

    else:
        raise bottle.HTTPError(403, "Auth-Secret error!")


# ######### static files

@route('/', method="GET")
def index():
    return bottle.static_file('index.html', root=os.path.join(os.getcwd(), 'static'))


@route('/favicon.ico', method="GET")
def favicon():
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
    try:
        dataj = json.loads(request.body.read().decode("utf-8"))
    except Exception as e:
        raise JsonRpcParseError(str(e))

    token = request.headers.get('API-Token', urltoken)

    try:
        if token is None:
            raise JsonRpcServerError("Token missing")
        if isinstance(dataj, list):
            logger.debug("Request is a list")
            res = []
            for rj in dataj:
                try:
                    res.append(do_handle_jsonrpc_request(request, rj, token))
                except JsonRpcError as err:
                    res.append(err.toJsonRpcMessage)
            response.headers['Content-Type'] = 'application/json'
            return res
        else:
            return do_handle_jsonrpc_request(request, dataj, token)
    except JsonRpcError as err:
        response.headers['Content-Type'] = 'application/json'
        return err.toJsonRpcMessage
    except Exception as e:
        logger.error(e)
        response.headers['Content-Type'] = 'application/json'
        return JsonRpcError(message=e).toJsonRpcMessage


def do_handle_jsonrpc_request(request, jsonrcp, token) -> dict:
    """
    Handle a single JSON-RPC request object
    :param request: bottle request object
    :param jsonrcp: JSON-RCP request dictionary/object
    :param token:   Security Token
    :return:        JSON-RPC response object
    :raises JsonRpcError: in case of error
    """
    try:
        request_id = jsonrcp.get('id')
    except AttributeError as ate:
        logger.debug("JSON request ID missing")
        raise JsonRpcInvalidRequest(str(ate))

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

        _mySdnFilter.filterResponse(resj)
        response.status = r.status_code
        return resj
    else:
        logger.debug("OpenSDNcore returned no json! headers: %s" % r.headers)
        raise JsonRpcInternalError("Invalid response from upstream server", id=request_id)


def do_validate_jsonrpc_request(token, rpcdata, id) -> None:
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
    logger.debug("using SDNFilter %s to validate request" % type(_mySdnFilter))

    if not _mySdnFilter.validateRequest(token, method, rpcdata.get("params", [])):
        raise JsonRpcServerError("Method not Allowed", code=-32043, id=id)


def start():
    global _mySdnFilter
    _experiments["test01"] = {"tenant": "123invalid456", "flow_tables": 300}
    logger.info("starting up")
    _mySdnFilter = WhitelistFilter(["help", "list.methods"])
    bottle.run(host='0.0.0.0', port=8001, reloader=True)
