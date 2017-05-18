#!/usr/bin/env python
import urllib

import bottle
import json
import os

import requests
from bottle import request, response
from bottle import post, get, put, delete, route
from utils import get_config, get_logger, make_jsonrpc_error

logger = get_logger(__name__)


_experiments = dict()
_auth_secret = "90d82936f887a871df8cc82c1518a43e"
_api_endpoint = "http://127.0.0.1:8001/"
_osdnc_api = "http://192.168.41.153:10010/"

def check_auth_header(headers):
    if "Auth-Secret" in headers.keys():
        auth_secret = headers.get("Auth-Secret")
        logger.debug("'Auth-Secret' header present! value: %s" %auth_secret)
        if auth_secret == _auth_secret:
            return True
    return False

def get_user_flowtables(tenant_id):
    return list(range(11, 21))

@post('/SDNproxySetup')
def proxy_creation_handler():
    '''Handles experiment/proxy creation
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
    '''
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
        return json.dumps( {"user-flow-tables":_experiments[experiment_id]["flow_tables"], "endpoint_url": _api_endpoint } )

    except:
        response.status = 500


@get('/SDNproxy')
def proxy_listing_handler():
    '''Handles name listing'''
    response.headers['Content-Type'] = 'application/json'
    response.headers['Cache-Control'] = 'no-cache'
    #return json.dumps(list(request.headers.items()))
    return json.dumps(_experiments)


@get('/SDNproxy/<token>')
def proxy_details_handler(token):
    '''Handles name updates'''

    if check_auth_header(request.headers):
        if token in _experiments:
            response.headers['Content-Type'] = 'application/json'
            response.headers['Cache-Control'] = 'no-cache'
            return json.dumps(_experiments[token])
        else:
            response.status = 404
    else:
        response.status = 403
        return "Auth-Secret error!"

@delete('/SDNproxy/<token>')
def delete_handler(token):
    '''delete the mapping between experiment-token and tenant id
    :returns  200 but no body
    '''
    if check_auth_header(request.headers):
        if _experiments.pop(token, None) is None:
            response.status = 404
            msg = "Experiment not found!"
        else:
            response.status = 200
            msg = "Experiment sccesfully deleted!"
        logger.debug(msg)
        response.headers['Content-Type'] = 'application/json'
        return json.dumps({"msg": msg})

    else:
        response.status = 403
        return "Auth-Secret error!"

@route('/', method="GET")
def index():
    return bottle.static_file('index.html', os.getcwd())

@post('/api')
def do_proxy_jsonrpc():
    logger.debug("JSONRCP: request.")
    dataj=json.loads(request.body.read().decode("utf-8"))
    logger.debug("data %s"% dataj)
    request_id = dataj.get('id')
    token = request.headers.get('API-Token')

    if do_filter_jsonrpc_request(token, dataj):
        r = requests.post(_osdnc_api, data=bottle.request.body, headers={'Content-Type': 'application/json-rpc'})

        logger.debug("Result status: %d " %(r.status_code))
        if r.headers.get('Content-Type') and r.headers['Content-Type'] == "application/json":
            try:
                resj = r.json()
            except Exception as e:
                response.status = 500
                logger.error("Error reading response json: %s" % e)
                return "500 Internal error parsing the response from OpenSDNcore!"
        else:
            logger.debug("OpenSDNcore returned no json! heders: %s" % r.headers)
            response.headers['Content-Type'] = 'application/json'
            return make_jsonrpc_error(request_id, -32600, "Invalid Request")

        logger.debug("Result from OpenSDNcore: %s" % resj)
        response.status = r.status_code
        return resj
    else:
        #response.status = 403
        #return "403 Request not allowed!"
        return make_jsonrpc_error(request_id, -32643, "Method not allowed or Token missing")


def do_filter_jsonrpc_request(token, data):
    allowed_methods = ["help", "list.methods"]

    if token is None:
        logger.info("Token not found in request!")
        return False

    experimenter = _experiments.get(token)
    if experimenter is None:
        logger.info("Invalid Token %s"%token)
        return False

    logger.debug("data: %s"%data)
    method = data.get("method")

    logger.debug("MEthod: %s"%method)

    if method is not None and method in allowed_methods:
        return True

    return False


def start():
    #_experiments["test01"]= {"tenant": 123, "username": "admin"}
    logger.info("starting up")
    bottle.debug(True)
    bottle.run(host = '127.0.0.1', port = 8001, reloader=True)