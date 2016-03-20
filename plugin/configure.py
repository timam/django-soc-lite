import os

import click

import requests


app_directory = os.path.join(os.path.expanduser("~"), ".plugin")

@click.command()
@click.argument("server")
def cli(server):
    r = requests.get("http://{0}:4040/client/register/python".format(server))
    client_id = r.text

    try:
        os.makedirs(app_directory)
    except OSError:
        pass

    with open(os.path.join(app_directory, "client_id"), "w+") as f:
        f.write(client_id)
