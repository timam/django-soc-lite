import os

import subprocess

from datetime import datetime

import click

import requests

from plugin import settings_directory


@click.command()
@click.argument("server")
@click.argument("port")
def cli(server, port):
    r = requests.get("http://{0}:{1}/client/register/python".format(
        server, port
    ))
    client_id = r.text

    try:
        os.makedirs(settings_directory)
    except OSError:
        pass

    with open(os.path.join(settings_directory, "client_id"), "w+") as f:
        f.write(client_id)

    with open(os.path.join(settings_directory, "server"), "w+") as f:
        f.write("{0}:{1}".format(server, port))

    versions = subprocess.check_output(["pip", "freeze"])
    requests.post("http://{0}:{1}/version/python".format(server, port), data={
        "client_id": client_id,
        "timestamp": datetime.utcnow(),
        "data": versions
    })

    with open(os.path.join(settings_directory, "last_updated"), "w+") as f:
        f.write(datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
