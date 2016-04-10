import os

import subprocess

from datetime import datetime

import requests

from plugin import client_id, port, server, settings_directory


def get_client_versions():
    versions = subprocess.check_output(["pip", "freeze"])
    requests.post("http://{0}:{1}/version/python".format(server, port), data={
        "client_id": client_id,
        "timestamp": datetime.utcnow(),
        "data": versions
    })


def send_client_info():
    with open(os.path.join(settings_directory, "last_updated"), "r") as f:
        last_updated = datetime.strptime(f.read(), "%Y-%m-%d %H:%M:%S")

    if (datetime.utcnow() - last_updated).days >= 1:
        get_client_versions()

        with open(os.path.join(settings_directory, "last_updated"), "r") as f:
            f.write(datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
