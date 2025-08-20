import ssl
import logging
import imaplib
from typing import Optional

from utils.ws_logger import WebSocketLogger


def connect(config: dict, log: logging.Logger, wsl: Optional[WebSocketLogger] = None) -> imaplib.IMAP4_SSL | imaplib.IMAP4:
	timeout = 15

	host = config['imap']['host']
	port = config['imap']['port']
	insecure = config['imap']['tlsinsecure']
	user = config['imap']['user']
	pwd = config['imap']['password']
	folder = config['imap']['folder']

	# Build SSL Context
	if insecure == "no":
		ctx = ssl.create_default_context()
	elif insecure == "yes":
		ctx = ssl._create_unverified_context()
	else:
		raise Exception("insecure must be 'yes' or 'no'")

	# Prefer implicit TLS (IMAP over SSL)
	try:
		conn = imaplib.IMAP4_SSL(host, port, ssl_context=ctx, timeout=timeout)
		conn.login(user, pwd)
		log.info('Connected to {0}@{1}:{2}/{3} using implicit tls. insecure={4}'.format(user, host, port, folder, insecure))
		if wsl is not None:
			wsl.emit_info('Connected to email {0} server {1}:{2}/{3} using implicit tls. insecure={4}'.format(user, host, port, folder, insecure))
		return conn
	except Exception as e_tls:
		# Fallback to STARTTLS
		conn = imaplib.IMAP4(host, port, timeout=timeout)
		conn.starttls(ssl_context=ctx)
		conn.login(user, pwd)
		log.info('Connected to {0}@{1}:{2}/{3} using Starttls. insecure={4}'.format(user, host, port, folder, insecure))
		if wsl is not None:
			wsl.emit_info('Connected to email {0} server {1}:{2}/{3} using Starttls. insecure={4}'.format(user, host, port, folder, insecure))
		return conn
