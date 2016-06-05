from __future__ import absolute_import, division, print_function

import os

import subprocess

from datetime import datetime

import click

import requests

from plugin import settings_directory


@click.command()
@click.argument("server")
@click.argument("port")
@click.argument("client_id")
@click.argument("source_dir", type=click.Path(exists=True))
def cli(server, port, client_id, source_dir):
    versions = subprocess.check_output(["pip", "freeze"])
    requests.post("http://{0}:{1}/version/python".format(server, port), data={
        "client_id": client_id,
        "timestamp": datetime.utcnow(),
        "data": versions
    })

    try:
        os.makedirs(settings_directory)
    except OSError:
        pass

    with open(os.path.join(settings_directory, "client_id"), "w+") as f:
        f.write(client_id)

    with open(os.path.join(settings_directory, "server"), "w+") as f:
        f.write("{0}:{1}".format(server, port))


    with open(os.path.join(settings_directory, "last_updated"), "w+") as f:
        f.write(datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))

    for root, dirs, files in os.walk(source_dir):
        for f in files:
            filepath = os.path.join(root, f)
            if filepath.endswith(".py"):
                with open(filepath, "r") as f:
                    data = f.read()

                with open(filepath, "w") as f:
                    f.write(
                        "from plugin import monkey; monkey.patch_all()\n\n" +
                        data
                    )
