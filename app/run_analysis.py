import logging.config
import json
import time
import traceback
from thehive4py import TheHiveApi
from thehive4py.types.case import OutputCase
from cortex4py.api import Api
import utils.log
import utils.whitelist
from utils.ws_logger import WebSocketLogger

# Global variable used for logging
log: logging.Logger


# Send the notification to the user
def notify_start_of_analysis(case: OutputCase, task_id, mail_to, wsl: WebSocketLogger, api_thehive: TheHiveApi,
							 api_cortex: Api):
	# Add a description to the first task that is understood by the Mailer responder and start it
	# The description must start with "mailto:<email>" and then continue with the body of the email to send to the user
	# Uses [11:] to filter out the prefix [ThePhish] in the name of the case
	task_update = {
		"description": "mailto:" + mail_to + "\nThanks for the submission. Your e-mail with subject [{0}] is being analyzed.".format(
			case.title[11:]),
		"status": "InProgress"
	}
	api_thehive.task.update(task_id=task_id, fields=task_update)

	# Obtain the representation of the Mailer responder
	mailer_responder = api_cortex.responders.get_by_name('Mailer_1_0')
	# Check if the responder has been enabled in Cortex
	if mailer_responder:
		# Obtain the ID of the Mailer responder and start the Mailer responder on the first task
		job_result = api_thehive.responder.run(
			responder_id=mailer_responder.id,
			object_type='case_task',
			object_id=task_id
		)
		job_mailer_id = job_result['cortexJobId']
		# Obtain the status of the job related to the Mailer responder and wait for its completion
		job_mailer_status = api_cortex.jobs.get_by_id(job_mailer_id).json()['status']
		while job_mailer_status not in ['Success', 'Failure']:
			time.sleep(2)
			job_mailer_status = api_cortex.jobs.get_by_id(job_mailer_id).json()['status']
		if job_mailer_status == 'Success':
			log.info('Notification mail sent')
			wsl.emit_info('Notification mail sent')
		else:
			log.warning('Something went wrong with the Mailer responder')
			wsl.emit_warning('Something went wrong with the Mailer responder')
	else:
		log.warning('The Mailer responder is not active')
		wsl.emit_warning('The Mailer responder is not active')
	# Close the task
	task_update = {
		"status": "Completed"
	}
	api_thehive.task.update(task_id=task_id, fields=task_update)


# Start the analyzers on the observables
def analyze_observables(case: OutputCase, task_id, wsl: WebSocketLogger, config: dict, api_thehive: TheHiveApi,
						api_cortex: Api, whitelist: dict, conf_analyzers_level: dict):
	# Start the second task
	task_update = {
		"status": "InProgress"
	}
	api_thehive.task.update(task_id=task_id, fields=task_update)

	# Obtain the observable list from the case
	observables_json = api_thehive.observable.get_all(case_id=case.id)

	# Create a list of jobs with:
	# - job_id
	# - id of the observable to which the job refers
	# - job status
	jobs = []

	# Create a list of delayed jobs with:
	# - analyzer name
	# - observable name on which to start the analyzer
	# - observable type on which to start the analyzer
	# - id of the observable on which to start the analyzer
	delayed_jobs = []

	# List that will contain the reports of each analyzer for each observable
	reports_observables = []

	# Create a list containing information about all the observables of the case with:
	# - Name
	# - Type
	# - Tags list
	# - alphanumeric ID
	observables_info = []

	# Dictionary that contains the list of enabled and applicable analyzers for each observable type
	applicable_analyzers = {}
	applicable_analyzers['file'] = api_cortex.analyzers.get_by_type('file')
	applicable_analyzers['url'] = api_cortex.analyzers.get_by_type('url')
	applicable_analyzers['domain'] = api_cortex.analyzers.get_by_type('domain')
	applicable_analyzers['ip'] = api_cortex.analyzers.get_by_type('ip')
	applicable_analyzers['mail'] = api_cortex.analyzers.get_by_type('mail')
	applicable_analyzers['hash'] = api_cortex.analyzers.get_by_type('hash')

	# For each observable, add its information to the dictionary
	for observable in observables_json:
		observable_info = {}
		# The needed information are in different places depending on the type of the observable
		if observable.data_type == 'file':
			observable_info['name'] = observable.attachment.name if hasattr(observable, 'attachment') else 'unknown'
			if hasattr(observable, 'attachment') and hasattr(observable.attachment, 'content_type'):
				if (observable.attachment.content_type == 'message/rfc822') or (
						observable.attachment.content_type in ['application/x-empty', 'text/plain'] and observable_info[
					'name'][-4:] == '.eml'):
					observable_info['type'] = observable.data_type + '_' + 'message/rfc822'
				else:
					observable_info['type'] = observable.data_type
			else:
				observable_info['type'] = observable.data_type
		else:
			observable_info['name'] = observable.data
			observable_info['type'] = observable.data_type
		observable_info['tags'] = observable.tags if hasattr(observable, 'tags') else []
		observable_info['id'] = observable.id
		observables_info.append(observable_info)

		# If it is the EML file, then create a new observable type and only execute yara
		if observable_info['type'] == 'file_message/rfc822':
			# Start the job related to the Yara analyzer if it is enabled
			for analyzer in applicable_analyzers['file']:
				if analyzer.name == 'Yara_3_0':
					# Create the job object
					job = {}
					# Run the analyzer and convert the response in JSON format, then obtain and save the job ID
					job_result = api_thehive.cortex.run_analyzer(
						cortex_id=config['cortex']['id'],
						artifact_id=observable_info['id'],
						analyzer_name=analyzer.name
					)
					job['job_id'] = job_result['cortexJobId']
					# Save the observable ID
					job['observable_id'] = observable_info['id']
					# Set the status to NotTerminated
					job['status'] = 'NotTerminated'
					# Add the job with all the needed information to the list
					jobs.append(job)
					log.info(
						"Started analyzer " + analyzer.name + " for " + observable_info['type'] + " " + observable_info[
							'name'])
					wsl.emit_info(
						"Started analyzer " + analyzer.name + " for " + observable_info['type'] + " " + observable_info[
							'name'])

		# Otherwise, if it is a URL, start the UnshortenLink analyzer
		if observable_info['type'] == 'url':
			for analyzer in applicable_analyzers[observable_info['type']]:
				if analyzer.name == 'UnshortenLink_1_2':
					# Start the UnshortenLink analyzer
					job_result = api_thehive.cortex.run_analyzer(
						cortex_id=config['cortex']['id'],
						artifact_id=observable_info['id'],
						analyzer_name='UnshortenLink_1_2'
					)
					job_ul_id = job_result['cortexJobId']
					log.info(
						"Started analyzer " + analyzer.name + " for " + observable_info['type'] + " " + observable_info[
							'name'])
					wsl.emit_info(
						"Started analyzer " + analyzer.name + " for " + observable_info['type'] + " " + observable_info[
							'name'])
					# Obtain the status of the job related to the UnshortenLink analyzer and wait for its completion
					job_ul_status = api_cortex.jobs.get_by_id(job_ul_id).json()['status']
					while job_ul_status not in ['Success', 'Failure']:
						time.sleep(2)
						job_ul_status = api_cortex.jobs.get_by_id(job_ul_id).json()['status']
					unshortened_url = ''
					# If a shortened link has been found, save it
					if job_ul_status == 'Success':
						job_ul = api_cortex.jobs.get_report(job_ul_id).json()
						if job_ul['report']['full']['found'] == True:
							unshortened_url = job_ul['report']['full']['url']
					# Add the unshortened link as an observable to the case if not whitelisted
					if len(unshortened_url) > 0:
						if utils.whitelist.is_whitelisted(whitelist, 'url', unshortened_url):
							log.info("Skipped whitelisted observable url: {0}".format(unshortened_url))
							wsl.emit_info("Skipped whitelisted observable url: {0}".format(unshortened_url))
						else:
							new_observable = {
								"dataType": 'url',
								"data": unshortened_url,
								"ioc": False,
								"tags": ['unshortened_url'],
								"message": 'Unshortened from {}'.format(observable_info['name'])
							}
							created_obs = api_thehive.observable.create(case_id=case.id, observable=new_observable)
							log.info('Added unshortened url: {} as observable'.format(unshortened_url))
							wsl.emit_info('Added unshortened url: {} as observable'.format(unshortened_url))
							# Add the just created observable also to the list of observables on which the cycle is running, so that it will be analyzed as well
							if created_obs:
								new_obs = api_thehive.observable.get(observable_id=created_obs.id)
								observables_json.append(new_obs)
								obs_unshortened_info = {}
								obs_unshortened_info['name'] = new_obs.data
								obs_unshortened_info['type'] = new_obs.data_type
								obs_unshortened_info['tags'] = new_obs.tags if hasattr(new_obs, 'tags') else []
								obs_unshortened_info['id'] = new_obs.id
								observables_info.append(obs_unshortened_info)
								log.info("Analyzer " + analyzer.name + " for " + observable_info['type'] + " " +
										 observable_info[
											 'name'] + " terminated. Added the url " + unshortened_url + " as new observable to the case.")
								wsl.emit_info("Analyzer " + analyzer.name + " for " + observable_info['type'] + " " +
											  observable_info[
												  'name'] + " terminated. Added the url " + unshortened_url + " as new observable to the case.")

		# Start all the applicable analyzers if the observable is not the EML file
		if observable_info['type'] != 'file_message/rfc822':
			for analyzer in applicable_analyzers[observable_info['type']]:
				# The DomainMailSPFDMARC_Analyzer should only be started on domains that should be able to send emails
				# It is started only on observables found in a subset of the header fields
				# which are the observables tagged as contained in the email header and, in particular, in one of the considered header fields
				# The third tag of the observable should be email_header_HEADERNAME, so the prefix email_header_ is removed
				header_fields_list_SPFDMARC = ['From', 'Sender', 'Return-Path', 'Reply-To', 'Bounces-to', 'Received',
											   'X-Received', 'X-OriginatorOrg', 'X-Originating-Email']
				if analyzer.name == 'DomainMailSPFDMARC_Analyzer_1_1' and not (
						observable_info['type'] == 'domain' and len(observable_info['tags']) > 2 and
						observable_info['tags'][1] == 'email_header' and observable_info['tags'][2][
							13:] in header_fields_list_SPFDMARC):
					continue
				# If it is an URL, do not start UnshortenLink again
				if observable_info['type'] == 'url' and analyzer.name == 'UnshortenLink_1_2':
					continue
				# Start the analyzer
				analyzer_job = api_thehive.cortex.run_analyzer(
					cortex_id=config['cortex']['id'],
					artifact_id=observable_info['id'],
					analyzer_name=analyzer.name
				)
				# If the rate limit is exceeded for a certain analyzer, the related job is not started
				# so the information needed to start the job later is added to a list of delayed jobs
				if "RateLimitExceeded" in str(analyzer_job):
					log.info(
						"Rate limit exceeded for analyzer " + analyzer.name + " for " + observable_info['type'] + " " +
						observable_info['name'] + ". It will be restarted in a while.")
					wsl.emit_info(
						"Rate limit exceeded for analyzer " + analyzer.name + " for " + observable_info['type'] + " " +
						observable_info['name'] + ". It will be restarted in a while.")
					delayed_job = {}
					delayed_job['analyzer_name'] = analyzer.name
					delayed_job['observable_name'] = observable_info['name']
					delayed_job['observable_type'] = observable_info['type']
					delayed_job['observable_id'] = observable_info['id']
					delayed_jobs.append(delayed_job)
				# else add the information of the job to the list of started jobs
				else:
					job = {}
					job['job_id'] = analyzer_job['cortexJobId']
					job['observable_id'] = observable_info['id']
					job['status'] = 'NotTerminated'
					jobs.append(job)
					log.info(
						"Started analyzer " + analyzer.name + " for " + observable_info['type'] + " " + observable_info[
							'name'])
					wsl.emit_info(
						"Started analyzer " + analyzer.name + " for " + observable_info['type'] + " " + observable_info[
							'name'])

	# Try to start the delayed analyzers until the list of delayed analyzers becomes empty
	while len(delayed_jobs) > 0:
		for delayed_job in delayed_jobs:
			# Try to start the analyzer
			analyzer_job = api_thehive.cortex.run_analyzer(
				cortex_id=config['cortex']['id'],
				artifact_id=delayed_job['observable_id'],
				analyzer_name=delayed_job['analyzer_name']
			)
			# If the rate limit is still exceeded for this analyzer, do not remove it from the list of delayed jobs
			if "RateLimitExceeded" in str(analyzer_job):
				log.info("Rate limit exceeded for analyzer " + delayed_job['analyzer_name'] + " for " + delayed_job[
					'observable_type'] + " " + delayed_job['observable_name'] + ". It will be restarted in a while.")
				wsl.emit_info(
					"Rate limit exceeded for analyzer " + delayed_job['analyzer_name'] + " for " + delayed_job[
						'observable_type'] + " " + delayed_job[
						'observable_name'] + ". It will be restarted in a while.")
			# Otherwise start the analyzer, add it to the list of started analyzers and remove it from the list of delayed analyzers
			else:
				job = {}
				job['job_id'] = analyzer_job['cortexJobId']
				job['observable_id'] = delayed_job['observable_id']
				job['status'] = 'NotTerminated'
				jobs.append(job)
				delayed_jobs.remove(delayed_job)
				log.info("Started analyzer " + delayed_job['analyzer_name'] + " for " + delayed_job[
					'observable_type'] + " " + delayed_job['observable_name'])
				wsl.emit_info("Started analyzer " + delayed_job['analyzer_name'] + " for " + delayed_job[
					'observable_type'] + " " + delayed_job['observable_name'])
		# Prevent continuous requests while waiting for the time needed to start an analyzer
		time.sleep(10)

	log.info("All the analysis jobs have been started, waiting for their completion...")
	wsl.emit_info("All the analysis jobs have been started, waiting for their completion...")

	# Wait for all the jobs to terminate
	terminated_jobs = 0
	# Wait until the number of terminated jobs is equal to the number of started jobs
	while terminated_jobs != len(jobs):
		# Prevent continuous requests while waiting for all the analyzers to terminate
		time.sleep(5)
		for job_obj in jobs:
			# Request the status of the job and if it is terminated increment the number of terminated jobs
			if job_obj['status'] == 'NotTerminated':
				job = api_cortex.jobs.get_by_id(job_obj['job_id']).json()
				if job['status'] == 'Success' or job['status'] == 'Failure':
					job_obj['status'] = job['status']
					terminated_jobs += 1

	log.info("All the analysis jobs terminated")
	wsl.emit_info("All the analysis jobs terminated")

	# For each observable, find the ID of all the analyzers started on that observable and use it to fetch the report of that analyzer (job)
	for observable_info in observables_info:
		for job_obj in jobs:
			if observable_info['id'] == job_obj['observable_id']:
				# Obtain the report
				job = api_cortex.jobs.get_report(job_obj['job_id']).json()
				# Add the report along with all the needed information on the observable and the analyzer to the list of reports
				report_obs = {}
				report_obs['observable_name'] = observable_info['name']
				report_obs['observable_type'] = observable_info['type']
				report_obs['observable_id'] = observable_info['id']
				report_obs['analyzer_name'] = job['analyzerName']
				# The report is populated only if the job terminated successfully
				report_obs['analyzer_result'] = ''
				if job['status'] == 'Success':
					# Handle the possibility that a job terminates successfully but the report does not contain the level
					# In that case the level defaults as "info"
					level = 'info'
					report = job.get('report')
					if report:
						summary = report.get('summary')
						if summary:
							taxonomies = summary.get('taxonomies')
							if taxonomies and len(taxonomies) > 0:
								# Handle Pulsedive
								# Many taxonomies are created, only the last one is needed
								if job['analyzerName'] == 'Pulsedive_GetIndicator_1_0':
									level = taxonomies[-1].get('level', 'info')
								# Handle IPVoid
								# Many taxonomies are created, only the last one is needed
								elif job['analyzerName'] == 'IPVoid_1_0':
									level = taxonomies[-1].get('level', 'info')
								# Handle Shodan
								# Many taxonomies are created, only the last one is needed
								# The other analyzers based on shodan only give "info" as level
								elif job['analyzerName'] in ['Shodan_Host_1_0', 'Shodan_Host_History_1_0']:
									level = taxonomies[-1].get('level', 'info')
								# Handle SpamhausDBL
								# The first taxonomy contains the return code that if it is among the codes listed below it means that the level should be malicious
								elif job['analyzerName'] == 'SpamhausDBL_1_0':
									if taxonomies[0].get('value', 'NXDOMAIN') in ['127.0.1.2', '127.0.1.4', '127.0.1.5',
																				  '127.0.1.6', '127.0.1.102',
																				  '127.0.1.103', '127.0.1.104',
																				  '127.0.1.105', '127.0.1.106']:
										level = 'malicious'
								# For all the other analyzers uses the first taxonomy
								else:
									level = taxonomies[0].get('level', 'info')

					# Handle URLhaus
					# md5_hash and sha256_hash are supported only for payload search and not also for URL or hosts (IP, domains)
					# Without this modification it is always given a level of "info" even though it should be "malicious"
					# So, if "info" is obtained, check in the full report if there is a threat and, if so, set the level to "malicious"
					if job['analyzerName'] == 'URLhaus_2_0' and job['report']['full']['query_status'] == 'ok' and \
							job['report']['full'].get('threat'):
						level = 'malicious'

					# Handle analyzers levels
					# Often happens that the level given by an analyzer is too high for some or all the observable types on which it is applicable, leading to false positives
					# It is then used a configuration file which is a dictionary containing, for each analyzer that has to be modified:
					# - dataType: types of the observables on which to apply the modification
					# - level mapping
					if job['analyzerName'] in conf_analyzers_level:
						if observable_info['type'] in conf_analyzers_level[job['analyzerName']]['dataType']:
							level = conf_analyzers_level[job['analyzerName']]['levelMapping'][level]

					# Save the level in the report
					report_obs['analyzer_result'] = level
					log.info(
						"Analyzer {0} terminated successfully for {1} {2} with verdict {3}".format(job['analyzerName'],
																								   report_obs[
																									   'observable_type'],
																								   report_obs[
																									   'observable_name'],
																								   report_obs[
																									   'analyzer_result']))
					wsl.emit_info(
						"Analyzer {0} terminated successfully for {1} {2} with verdict {3}".format(job['analyzerName'],
																								   report_obs[
																									   'observable_type'],
																								   report_obs[
																									   'observable_name'],
																								   report_obs[
																									   'analyzer_result']))
				else:
					log.warning("Something went wrong with analyzer {0} for {1} {2}: {3}".format(job['analyzerName'],
																								 report_obs[
																									 'observable_type'],
																								 report_obs[
																									 'observable_name'],
																								 job))
					wsl.emit_warning("Something went wrong with analyzer {0} for {1} {2}".format(job['analyzerName'],
																								 report_obs[
																									 'observable_type'],
																								 report_obs[
																									 'observable_name']))

				# Add the report to the list of reports
				reports_observables.append(report_obs)

	# Close the second task
	task_update = {
		"status": "Completed"
	}
	api_thehive.task.update(task_id=task_id, fields=task_update)

	return observables_info, reports_observables


def terminate_analysis(case: OutputCase, task_id, mail_to, observables_info, reports_observables, wsl: WebSocketLogger,
					   config: dict, api_thehive: TheHiveApi, api_cortex: Api):
	# Start the third task
	task_update = {
		"status": "InProgress"
	}
	api_thehive.task.update(task_id=task_id, fields=task_update)

	# Initialize the number of malicious and suspicious observables to 0
	malicious_observables = 0
	suspicious_observables = 0

	# Count the number of malicious and suspicious reports for each observable
	for observable_info in observables_info:
		malicious_reports = 0
		suspicious_reports = 0
		for report_obs in reports_observables:
			if report_obs['observable_id'] == observable_info['id']:
				if report_obs['analyzer_result'] == 'malicious':
					malicious_reports += 1
				elif report_obs['analyzer_result'] == 'suspicious':
					suspicious_reports += 1
			# If the number of malicious reports is > 0 for this observable, the observable is malicious
		if malicious_reports > 0:
			malicious_observables += 1
			# Mark the observable as IoC
			obs_update = {"ioc": True}
			api_thehive.observable.update(observable_id=observable_info['id'], fields=obs_update)
		# If the number of suspicious reports is > 0 for this observable, the observable is suspicious
		if suspicious_reports > 0:
			suspicious_observables += 1

	# If there is at least one malicious observable, then the email is malicious
	if malicious_observables > 0:
		verdict = "Malicious"
	# If there is at least one suspicious observable, then the email is suspicious
	elif suspicious_observables > 0:
		verdict = "Suspicious"
	# Else the email is safe
	else:
		verdict = "Safe"
	log.info("The email has been classified as " + verdict)
	wsl.emit_info("The email has been classified as " + verdict)

	# If the verdict is final close the task and the case
	if verdict != "Suspicious":

		if verdict == 'Malicious':
			# If the verdict is malicious, export also the case to MISP along with the observables marked as IoC
			export_result = api_thehive.case.export_to_misp(
				case_id=case.id,
				misp_name=config['misp']['id']
			)
			if export_result:
				log.info("Case exported to MISP")
				wsl.emit_info("Case exported to MISP")
			else:
				log.warning("An error occurred during the export to MISP")
				wsl.emit_warning("An error occurred during the export to MISP")
			resolution_status = 'TruePositive'
			impact_status = 'NoImpact'

		elif verdict == 'Safe':
			resolution_status = 'FalsePositive'
			impact_status = 'NotApplicable'

		# Add a description to the third task that is understood by the Mailer responder
		# The description must start with "mailto:<email>" and then continue with the body of the email to send to the user
		task_update = {
			"description": "mailto:" + mail_to + "\nThanks for your submission. The e-mail with subject [{0}] you submitted has been classified as {1}".format(
				case.title[11:], verdict)
		}
		api_thehive.task.update(task_id=task_id, fields=task_update)
		# Obtain the representation of the Mailer responder
		mailer_responder = api_cortex.responders.get_by_name('Mailer_1_0')
		# Check if the responder has been enabled in Cortex
		if (mailer_responder):
			# Obtain the ID of the Mailer responder and start the Mailer responder on the third task
			job_result = api_thehive.responder.run(
				responder_id=mailer_responder.id,
				object_type='case_task',
				object_id=task_id
			)
			job_mailer_id = job_result['cortexJobId']
			# Obtain the status of the job related to the Mailer responder and wait for its completion
			job_mailer_status = api_cortex.jobs.get_by_id(job_mailer_id).json()['status']
			while job_mailer_status not in ['Success', 'Failure']:
				time.sleep(2)
				job_mailer_status = api_cortex.jobs.get_by_id(job_mailer_id).json()['status']
			if job_mailer_status == 'Success':
				log.info('Response mail sent')
				wsl.emit_info('Response mail sent')
			else:
				log.warning('Something went wrong with the Mailer responder')
				wsl.emit_warning('Something went wrong with the Mailer responder')
		else:
			log.warning('The Mailer responder is not active')
			wsl.emit_warning('The Mailer responder is not active')
		# Close the task
		task_update = {
			"status": "Completed"
		}
		api_thehive.task.update(task_id=task_id, fields=task_update)

		# Close the case
		case_update = {
			"status": "Resolved",
			"resolutionStatus": resolution_status,
			"impactStatus": impact_status,
			"summary": "Automated analysis"
		}
		api_thehive.case.update(case_id=case.id, fields=case_update)
		log.info("Case resolved as " + resolution_status)
		wsl.emit_info("Case resolved as " + resolution_status)

	# If the verdict is not final, leave the third task and the case open
	else:
		# Update the description of the third task
		task_update = {
			"description": "mailto:" + mail_to + "\n---> INSERT BODY OF THE E-MAIL TO SEND <---"
		}
		api_thehive.task.update(task_id=task_id, fields=task_update)

	return verdict


# Main function called from outside
# The wsl is not a global variable to support multiple tabs
# The mail_to parameter is the email address of the user to send notifications to
def main(config: dict, wsl: WebSocketLogger, case: OutputCase, mail_to):
	# Create Logger
	global log
	log = utils.log.get_logger("run_analysis")
	if log is None:
		return None

	# Load whitelist
	whitelist = utils.whitelist.load(log, wsl)
	if whitelist is None:
		return None

	# Create thehive api
	try:
		insecure = config['thehive']['tlsinsecure']
		if insecure == "no":
			verifycert = True
		elif insecure == "yes":
			verifycert = False
		else:
			raise Exception("insecure must be 'yes' or 'no'")

		# Object needed to use TheHive4py v2
		api_thehive = TheHiveApi(
			url=config['thehive']['url'],
			apikey=config['thehive']['apikey'],
			verify=verifycert
		)
	except Exception as e:
		log.error("Error while trying to create thehive api: {}".format(traceback.format_exc()))
		wsl.emit_error("Error while trying to create thehive api")
		return None

	# Create cortex api
	try:
		insecure = config['cortex']['tlsinsecure']
		if insecure == "no":
			verifycert = True
		elif insecure == "yes":
			verifycert = False
		else:
			raise Exception("insecure must be 'yes' or 'no'")

		# Object needed to use Cortex4py
		api_cortex = Api(config['cortex']['url'], config['cortex']['apikey'], verify_cert=verifycert)
	except Exception as e:
		log.error("Error while trying to create cortex api: {}".format(traceback.format_exc()))
		wsl.emit_error("Error while trying to create cortex api")
		return None

	# Read the configuration file for the analyzers levels modification
	try:
		with open("conf/analyzers_level_conf.json") as conf_file:
			conf_analyzers_level = json.load(conf_file)
	except Exception as e:
		log.error(
			"Error while trying to open the file 'conf/analyzers_level_conf.json': {}".format(traceback.format_exc()))
		wsl.emit_error("Error while trying to open the file 'conf/analyzers_level_conf.json'")
		return None

	# Obtain the IDS of the three task of the case
	tasks = api_thehive.task.get_all(case_id=case.id)
	task_ids = {}
	for task in tasks:
		if task.title == "ThePhish notification":
			task_ids['Notification'] = task.id
		elif task.title == "ThePhish analysis":
			task_ids['Analysis'] = task.id
		elif task.title == "ThePhish result":
			task_ids['Result'] = task.id

	# Call the notify_start_of_analysis function
	try:
		notify_start_of_analysis(case, task_ids['Notification'], mail_to, wsl, api_thehive, api_cortex)
	except Exception as e:
		log.error("Error while trying to notify the start of analysis: {}".format(traceback.format_exc()))
		wsl.emit_error("Error while trying to notify the start of analysis")
		return None

	# Call the analyze_observables function
	try:
		observables_info, reports_observables = analyze_observables(case, task_ids['Analysis'], wsl, config,
																	api_thehive, api_cortex, whitelist,
																	conf_analyzers_level)
	except Exception as e:
		log.error("Error during the analysis task: {}".format(traceback.format_exc()))
		wsl.emit_error("Error during the analysis task")
		return None

	# Call the terminate_analysis function
	try:
		verdict = terminate_analysis(case, task_ids['Result'], mail_to, observables_info, reports_observables, wsl,
									 config, api_thehive, api_cortex)
	except Exception as e:
		log.error("Error during the termination of the analysis: {}".format(traceback.format_exc()))
		wsl.emit_error("Error during the termination of the analysis")
		return None

	return verdict
