import eventlet
eventlet.monkey_patch()

import flask
import flask_socketio
from utils.ws_logger import WebSocketLogger
import list_emails
import case_from_email
import run_analysis
import markupsafe
import utils.log
import json
import traceback

# Monkeypatches the standard library to replace its key elements with green equivalents (greenlets)
# This is needed for websocket to work and avoid falling back to long polling
eventlet.monkey_patch()

app = flask.Flask(__name__, template_folder='web/templates', static_folder='web/static')
socketio = flask_socketio.SocketIO(app)

# Create global variables log and config
log = None
config = {}

# The main page
@app.route("/")
def homepage():
	return flask.render_template("index.html")

@app.route('/list', methods = ['GET'])
def obtain_emails_to_analyze():
	# Obtain the list of emails
	emails_info = list_emails.main(config)

	# Format and return
	response = flask.jsonify(emails_info)
	return response

# Analyze the email and obtain the verdict
@app.route('/analysis', methods = ['POST'])
def analyze_email():
	# UID of the email to analyze and sid of the client obtained from the request
	mail_uid = markupsafe.escape(flask.request.form.get("mailUID"))
	sid_client = markupsafe.escape(flask.request.form.get("sid"))

	# Instantiate the object used for logging by the other modules
	wsl = WebSocketLogger(socketio, sid_client)

	# Call the modules used to create the case and run the analysis
	new_case_id, external_from_field = case_from_email.main(wsl, mail_uid)
	verdict = run_analysis.main(wsl, new_case_id, external_from_field)

	# Format response and return
	response = flask.jsonify(verdict)
	return response

# If eventlet or gevent are installed, their wsgi server will be used
# else Werkzeug will be used
if __name__ == "__main__":
	# get logger for main
	log = utils.log.get_logger("thephish_app")
	if log is None:
		exit(1)

	# load config
	try:
		with open('conf/configuration.json') as conf_file:
			config = json.load(conf_file)
	except Exception as e:
		log.error("Error while trying to open the file 'conf/configuration.json': {}".format(traceback.format_exc()))
		exit(1)

	# run application
	socketio.run(app, host='0.0.0.0', port=8080)

