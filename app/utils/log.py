import json
import logging
import logging.config
import traceback
from typing import Optional


def get_logger(name: str) -> Optional[logging.Logger]:
	# Logging configuration
	try:
		with open('conf/logging_conf.json') as log_conf:
			log_conf_dict = json.load(log_conf)
			logging.config.dictConfig(log_conf_dict)
	except Exception as e:
		print("[ERROR]_[list_emails]: Error while trying to open the file 'conf/logging_conf.json'. It cannot be read or it is not valid: {}".format(traceback.format_exc()))
		return None

	return logging.getLogger(name)
