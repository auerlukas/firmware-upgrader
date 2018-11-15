# import stdlib
import logging
from threading import Thread

# import third party lib
from flask import Flask
from flask import render_template, flash, redirect
from flask import request
from functools import partial
from openVulnQuery._library.advisory import AdvisoryIOS
from queue import Queue
from typing import List
import threading
import urllib3
from nornir.core import InitNornir


# import custom
from config import Config
import forms
import ntbx
import orch

# @TODO comments/documentation
# @TODO type hinting
# @TODO logging
# @TODO unit tests
# @TODO queueing
# @TODO interface with netbox
# @TODO methoden in eigenes file auslagern


# Flask application
app = Flask(__name__)
app.config.from_object(Config)

# Job Queue
# needed to make sure that actions from multiple users do not conflict with eachother - work sequentially
jobs = Queue()

# Nornir
nr = InitNornir(config_file='nornir/config.yaml', dry_run=True)


# ##################################################################################################
# ##################################################################################################
#                                                                                                  #
# FLASK ROUTES                                                                                     #
#                                                                                                  #
# ##################################################################################################
# ##################################################################################################
@app.route("/")
def start():
    return render_template('index.html')


@app.route("/sites")
def sites_index():
    sites = orch.get_sites()
    return render_template('sites/index.html', sites=sites)


@app.route("/inventory")
def inventory_index():
    devices = orch.get_devices(nr)
    return render_template('inventory/index.html', devices=devices)


@app.route("/firmware")
def firmware_index():
    return render_template('firmware/index.html')


@app.route("/firmware/show")
def firmware_show():
    # getting firmware takes quite a bit of time
    # therefore create a job and put it into the job queue
    job = {'function': 'orch.get_firmware'}
    jobs.put(job)

    # jump to inventory index page
    return render_template('firmware/index.html')

    # devices = orch.get_firmware()
    # return render_template('firmware/show.html', devices=devices)


@app.route("/vulnerabilities")
def vulnerabilities_index():
    return render_template('vulnerabilities/index.html')


@app.route("/vulnerabilities/show")
def vulnerabilities_show() -> List[AdvisoryIOS]:
    os = request.args.get('os')
    version = request.args.get('version')

    vulnerabilities = orch.find_vulnerabilities(os, version)
    return render_template('vulnerabilities/show.html', vulnerabilities=vulnerabilities, os=os, version=version)


@app.route("/resetter")
def resetter_index():
    devices = orch.get_devices(nr)
    return render_template('resetter/index.html', devices=devices)


@app.route("/resetter/reload")
def reload():
    hostname = request.args.get('hostname')

    # # creating a job ID
    # job_id = 'reload_{h}'.format(h=hostname)
    #
    # # simple version
    # # job = q.enqueue(reload_switch, hostname)
    #
    # # explicit version
    # job = q.enqueue_call(func=orch.reload_switch(),
    #                      args=(hostname,),
    #                      job_id=job_id)

    # create a new job 'reload_switch' and put it to the job queue
    job = partial(orch.reload_switch, hostname=hostname)
    jobs.put(job)
    return render_template('resetter/reload.html', hostname=hostname)


@app.route("/resetter/reload_status")
def reload_status():
    hostname = request.args.get('hostname')
    j = jobs.get()
    print('size of job queue:')

    # debugging outputs
    # job = q.fetch_job('reload_{h}'.format(h=hostname))
    # if job is None:
    #     print('Job is None.')
    # else:
    #     print('Job Status: {s}'.format(s=job.get_status()))
    #     print('Job Result: {r}'.format(r=job.result))
    #     print('Job ID: {i}'.format(i=job.id))
    #
    # job_id = request.args.get('job_id')

    return render_template('resetter/reload_status.html', hostname=hostname)


@app.route("/netbox", methods=['GET', 'POST'])
def netbox_index():
    sites = ntbx.get_sites()['results']
    form = forms.IPAddressForm()
    if form.validate_on_submit():
        result = ntbx.add_ip_address(form.ip_address.data, form.prefix_length.data)
        flash(result)
        return redirect('/netbox')
    return render_template('netbox/index.html', sites=sites, ip_addr_form=form)


@app.route("/jobmanager")
def jobmanager_index():
    # get all running threads
    threads = threading.enumerate()
    jobs_list = list(jobs.queue)
    no_of_jobs = len(jobs_list)
    return render_template('jobmanager/index.html', threads=threads, jobs=jobs_list, no_of_jobs=no_of_jobs)



def job_manager():
    """
    job manager running permanently in the background as its own thread.
    handles various (long running) jobs
    :return:
    """
    logging.info('Job manager started.')
    while True:
        print('job manager: waiting for queue...')
        logging.info('waiting for queue...')

        # get job from queue (block=True is important here)
        # returns a pointer to job (element in queue), that's why it can be called later on using 'job()'
        job = jobs.get(block=True)

        print(job)
        if job['function'] == 'orch.get_firmware':
            # execute job
            print('executing %s' % job)
            logging.info('executing %s' % job)
            orch.get_firmware(nr)
            print('finished %s' % job)
            logging.info('finished %s' % job)

        jobs.task_done()


if __name__ == '__main__':
    logging.basicConfig(filename='../log/app.log', level=logging.INFO)

    logging.info('disabling InsecureRequestWarnings...')
    # suppress InsecureRequestWarnings
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # create a new thread which runs in the background and handles a job queue
    job_manager = Thread(target=job_manager, name='JobManager')
    job_manager.start()

    # run flask web app
    logging.info('starting web application..')
    app.run(host='127.0.0.1', port=5000, debug=True)
    # run_nornir()
