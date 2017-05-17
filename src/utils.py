import configparser
import os

import logging
import logging.config

CONFIG_FILE_PATH = './sdn-proxy.ini'

_logger = dict()

def get_logger(name):
    logging.config.fileConfig(CONFIG_FILE_PATH)
    if _logger.get(name) is None:
        _logger[name] = logging.getLogger("eu.softfire.%s"%name)
    return _logger[name]


def get_config():
    """
    """
    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_FILE_PATH) and os.path.isfile(CONFIG_FILE_PATH):
        config.read(CONFIG_FILE_PATH)
        return config
    else:
        logging.error("Config file not found, create %s" % CONFIG_FILE_PATH)
        exit(1)

def make_jsonrpc_error(responseid,code, message, version="2.0"):
    return dict(id=responseid, error=dict(message=message, code=code), jsonrpc=version)

def make_jsonrpc_response(responseid, result, version="2.0"):
    return dict(id=responseid,jsonrpc=version,result=result)