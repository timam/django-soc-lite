import os

import click

import requests

from plugin import settings_directory


@click.command()
@click.argument("server")
def cli(server):
    r = requests.get("http://{0}:4040/client/register/python".format(server))
    client_id = r.text

    try:
        os.makedirs(settings_directory)
    except OSError:
        pass

    with open(os.path.join(settings_directory, "client_id"), "w+") as f:
        f.write(client_id)
