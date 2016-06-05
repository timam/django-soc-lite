import os

import subprocess

from datetime import datetime

import requests

from plugin import client_id, port, server, settings_directory


class ServerUnreachableError(Exception):
    pass


def get_client_versions():
    try:
        versions = subprocess.check_output(["pip", "freeze"])
    except subprocess.CalledProcessError:
        # Preempt any subprocess error. TODO: Figure out how to make this
        # more robust against errors.
        return None

    r = requests.post("http://{0}:{1}/version/python".format(
        server, port
    ), data={
        "client_id": client_id,
        "timestamp": datetime.utcnow(),
        "data": versions
    })

    if r.status_code != 200:
        raise ServerUnreachableError(
            "HTTP Status code: {}".format(r.status_code)
        )


def send_client_info():
    with open(os.path.join(settings_directory, "last_updated"), "r") as f:
        last_updated = datetime.strptime(f.read(), "%Y-%m-%d %H:%M:%S")

    if (datetime.utcnow() - last_updated).days >= 1:
        try:
            get_client_versions()

            with open(
                    os.path.join(settings_directory, "last_updated"), "r"
            ) as f:
                f.write(datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
        except ServerUnreachableError:
            pass
