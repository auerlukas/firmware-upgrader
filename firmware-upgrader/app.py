# import stdlib
import logging
import os
import subprocess
import threading
import urllib3
from functools import partial
from queue import Queue
from threading import Thread
from typing import List

# import third party lib
from flask import Flask
from flask import render_template, flash, redirect
from flask import request
from openVulnQuery._library.advisory import AdvisoryIOS

# import custom
import forms
import ntbx
import orch
from config import Config

# @TODO comments/documentation
# @TODO type hinting
# @TODO logging
# @TODO unit tests


# Flask application
app = Flask(__name__)
app.config.from_object(Config)

# Job Queue
# needed to make sure that actions from multiple users do not conflict with eachother - working off tasks sequentially
jobs = Queue()

# Netbox
ntbx_api_url_base = 'not_ready'
ntbx_status = False


# make variable 'netbox' available in jinja templates
@app.context_processor
def inject_netbox_status():
    return dict(netbox_status=ntbx_status)


# ##################################################################################################
# ##################################################################################################
#                                                                                                  #
# FLASK ROUTES START                                                                               #
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
    devices = orch.get_devices()
    return render_template('inventory/index.html', devices=devices)


@app.route("/firmware")
def firmware_index():
    return render_template('firmware/index.html')


@app.route("/firmware/show")
def firmware_show():
    # getting firmware takes quite a bit of time
    # therefore create a job and put it into the job queue
    # job = {'function': 'orch.get_firmware'}
    job = partial(orch.get_firmware)
    jobs.put(job)

    # jump to inventory index page
    return render_template('firmware/index.html')


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
    devices = orch.get_devices()
    return render_template('resetter/index.html', devices=devices)


@app.route("/resetter/reload")
def reload():
    hostname = request.args.get('hostname')

    # TODO adopt to new queueing mechanism
    # create a new job 'reload_switch' and put it to the job queue
    j = partial(orch.reload_switch(hostname))
    jobs.put(j)
    return render_template('resetter/reload.html', hostname=hostname)


@app.route("/resetter/reload_status")
def reload_status():
    hostname = request.args.get('hostname')
    return render_template('resetter/reload_status.html', hostname=hostname)


@app.route("/netbox", methods=['GET', 'POST'])
def netbox_index():
    global ntbx_api_url_base
    sites = ntbx.get_sites(ntbx_api_url_base)['results']
    ip_addresses = ntbx.get_ip_addresses(ntbx_api_url_base)['results']
    form = forms.IPAddressForm()
    if form.validate_on_submit():
        result = ntbx.add_ip_address(ntbx_api_url_base, form.ip_address.data, form.prefix_length.data)
        flash(result)
        return redirect('/netbox')
    return render_template('netbox/index.html', sites=sites, ip_addr_form=form, ip_addresses=ip_addresses)


@app.route("/jobmanager")
def jobmanager_index():
    # get all running threads
    threads = threading.enumerate()
    jobs_list = list(jobs.queue)
    no_of_jobs = len(jobs_list)
    return render_template('jobmanager/index.html', threads=threads, jobs=jobs_list, no_of_jobs=no_of_jobs)


# ##################################################################################################
# ##################################################################################################
#                                                                                                  #
# FLASK ROUTES END                                                                               #
#                                                                                                  #
# ##################################################################################################
# ##################################################################################################


def job_manager():
    """
    job manager running permanently in the background as its own thread.
    handles various (long running) jobs
    :return:
    """
    logging.warning('Job manager started.')
    while True:
        print('job manager: waiting for queue...')
        logging.warning('waiting for queue...')

        # get job from queue (block=True is important here)
        # returns a pointer to job (element in queue), that's why it can be called later on using 'job()'
        job = jobs.get(block=True)

        print(f'job_manager: running job \'{job}\'')
        logging.warning('executing %s' % job)
        print('executing %s' % job)
        job()
        logging.warning('finished %s' % job)
        print('finished %s' % job)

        jobs.task_done()


def start_netbox():
    # start netbox containers
    logging.warning('starting netbox containers...')
    result = subprocess.Popen('cd /home/luk/dev/netbox-docker; docker-compose up -d',
                              shell=True, stdout=subprocess.PIPE).stdout.read()

    # find out IP address and TCP port on which netbox is running
    ntbx_socket = subprocess.Popen('cd /home/luk/dev/netbox-docker; docker-compose port nginx 8080',
                                   shell=True, stdout=subprocess.PIPE).stdout.read()

    ntbx_socket = ntbx_socket.decode('ascii').strip()

    # construct netbox api base url
    global ntbx_api_url_base
    ntbx_api_url_base = f'http://{ntbx_socket}/api/'
    global ntbx_status
    ntbx_status = True
    return result


if __name__ == '__main__':
    logging.basicConfig(filename='../log/app.log', level=logging.WARNING)

    # suppress InsecureRequestWarnings
    logging.warning('disabling InsecureRequestWarnings...')
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # create a new thread which runs in the background and handles a job queue
    job_manager = Thread(target=job_manager, name='JobManager')
    job_manager.start()

    # netbox
    # find out IP address and TCP port on which netbox is running (actually the nginx container belonging to netbox)
    ntbx_socket = subprocess.Popen('cd /home/luk/dev/netbox-docker; docker-compose port nginx 8080',
                                   shell=True, stdout=subprocess.PIPE).stdout.read()
    ntbx_socket = ntbx_socket.decode('ascii').strip()

    # construct netbox api base url
    ntbx_api_url_base = f'http://{ntbx_socket}/api/'

    # start netbox containers if not yet running
    if not ntbx_socket:
        job = partial(start_netbox)
        jobs.put(job)
    else:
        ntbx_status = True

    # run flask web app
    logging.warning('starting flask web application..')
    app.run(host='127.0.0.1', port=5000, debug=True)
