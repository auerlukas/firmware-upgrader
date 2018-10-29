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
def vulnerabilities_show() -> List[openVulnQuery.advisory.AdvisoryIOS]:
    os = request.args.get('os')
    version = request.args.get('version')

    vulnerabilities = find_vulnerabilities(os, version)
    return render_template('vulnerabilities/show.html', vulnerabilities=vulnerabilities, os=os, version=version)


@app.route("/reloader")
def reloader_index():
    result = q.enqueue(reload_switch)
    return render_template('reloader/index.html')


if __name__ == '__main__':
    print("PATH: ")
    print(sys.path)
    logging.basicConfig(filename='../log/app.log', level=logging.INFO)

    logging.debug('disabling InsecureRequestWarnings...')
    # suppress InsecureRequestWarnings
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # run flask web app
    logging.info('starting web application..')
    app.run(debug=True)
    # run_nornir()
