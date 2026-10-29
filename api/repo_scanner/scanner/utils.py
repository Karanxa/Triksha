import logging
import yaml


def load_config(path: str) -> dict:
    try:
        with open(path, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logging.getLogger("repo_scanner").error("Config file not found: %s", path)
        return {}
    except yaml.YAMLError as e:
        logging.getLogger("repo_scanner").error("Error parsing config file %s: %s", path, e)
        return {}


logger = logging.getLogger("repo_scanner")
