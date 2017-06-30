import configparser
import json
import logging
import logging.config
import os

CONFIG_FILE_PATH = '/etc/softfire/sdn-proxy.ini'

_logger = dict()


def get_logger(name):
    print("config_file: %s" % CONFIG_FILE_PATH)
    logging.config.fileConfig(CONFIG_FILE_PATH)
    if _logger.get(name) is None:
        _logger[name] = logging.getLogger("eu.softfire.%s" % name)
    return _logger[name]


def get_config_parser() -> configparser.ConfigParser:
    """
    """
    config = configparser.ConfigParser()
    print("config_file: %s" % CONFIG_FILE_PATH)
    if os.path.exists(CONFIG_FILE_PATH) and os.path.isfile(CONFIG_FILE_PATH):
        config.read(CONFIG_FILE_PATH)
        return config
    else:
        logging.error("Config file not found, create %s" % CONFIG_FILE_PATH)
        exit(1)


def get_config(section, key, default=None, config: configparser.ConfigParser = None):
    if not config:
        config = get_config_parser()
    if default is None:
        return config.get(section=section, option=key)
    try:
        return config.get(section=section, option=key)
    except configparser.NoOptionError:
        return default


def load_experiments(config: configparser.ConfigParser = None) -> dict:
    filename = get_config("sdn", "experiments-storage-filename", default="/etc/softfire/sdn-proxy-experiments.json",
                          config=config)
    try:
        if os.path.exists(filename) and os.path.isfile(filename):
            with open(filename, 'r') as f:
                return json.loads(f.read())
        else:
            return dict()
    except ValueError:
        return dict()


def store_experiments(experiments: dict, config: configparser.ConfigParser = None):
    if experiments:
        filename = get_config("sdn", "experiments-storage-filename", default="/etc/softfire/sdn-proxy-experiments.json",
                              config=config)
        with open(filename, 'w') as f:
            f.write(json.dumps(experiments))


def make_jsonrpc_error(responseid, code, message, version="2.0"):
    return dict(id=responseid, error=dict(message=message, code=code), jsonrpc=version)


def make_jsonrpc_response(responseid, result, version="2.0"):
    return dict(id=responseid, jsonrpc=version, result=result)
