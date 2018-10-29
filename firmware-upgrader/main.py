from redis import Redis
from rq import Queue

from app import *

# @TODO comments/documentation
# @TODO type hinting
# @TODO logging
# @TODO unit tests
# @TODO queueing
# @TODO interface with netbox
# @TODO methoden in eigenes file auslagern


app = Flask(__name__)
q = Queue(connection=Redis())
# nr = InitNornir(config_file='nornir/config.yaml')
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
    sites = get_sites()
    return render_template('sites/index.html', sites=sites)


@app.route("/inventory")
def inventory_index():
    devices = get_devices()
    return render_template('inventory/index.html', devices=devices)


@app.route("/firmware")
def firmware_index():
    return render_template('firmware/index.html')


@app.route("/firmware/show")
def firmware_show():
    devices = get_firmware()
    return render_template('firmware/show.html', devices=devices)


@app.route("/vulnerabilities")
def vulnerabilities_index():
    return render_template('vulnerabilities/index.html')


@app.route("/vulnerabilities/show")
def vulnerabilities_show() -> List[AdvisoryIOS]:
    os = request.args.get('os')
    version = request.args.get('version')

    vulnerabilities = find_vulnerabilities(os, version)
    return render_template('vulnerabilities/show.html', vulnerabilities=vulnerabilities, os=os, version=version)


@app.route("/resetter")
def resetter_index():
    devices = get_devices()
    return render_template('resetter/index.html', devices=devices)


@app.route("/resetter/reload")
def reload():
    hostname = request.args.get('hostname')

    # creating a job ID
    job_id = 'reload_{h}'.format(h=hostname)

    # simple version
    # job = q.enqueue(reload_switch, hostname)

    # explicit version
    job = q.enqueue_call(func=reload_switch,
                         args=(hostname,),
                         job_id=job_id)

    return render_template('resetter/reload.html', hostname=hostname, job_id=job_id)


@app.route("/resetter/reload_status")
def reload_status():
    hostname = request.args.get('hostname')

    # debugging outputs
    job = q.fetch_job('reload_{h}'.format(h=hostname))
    if job is None:
        print('Job is None.')
    else:
        print('Job Status: {s}'.format(s=job.get_status()))
        print('Job Result: {r}'.format(r=job.result))
        print('Job ID: {i}'.format(i=job.id))

    job_id = request.args.get('job_id')

    return render_template('resetter/reload_status.html', hostname=hostname, job=job, job_status=job.get_status())


if __name__ == '__main__':
    logging.basicConfig(filename='../log/app.log', level=logging.INFO)

    logging.debug('disabling InsecureRequestWarnings...')
    # suppress InsecureRequestWarnings
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # run flask web app
    logging.info('starting web application..')
    app.run(debug=True)
    # run_nornir()
