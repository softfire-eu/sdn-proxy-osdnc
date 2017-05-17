
import bottle
import json
import utils
import osdn_proxy_api

from utils import get_config, get_logger

logger = get_logger(__name__)

if __name__ == '__main__':
    #_experiments["test01"]= {"tenant": 123, "username": "admin"}
    logger.info("starting up")
    osdn_proxy_api.start()