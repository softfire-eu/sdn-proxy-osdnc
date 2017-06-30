import osdn_proxy_api
import utils
from utils import get_logger

logger = get_logger(__name__)

if __name__ == '__main__':
    logger.info("starting up")
    osdn_proxy_api.start(utils.get_config_parser())
