import os

import click

import requests


@click.command()
@click.argument("server")
def cli(server):
    r = requests.get("http://{0}:4040/client/register/python".format(server))
    client_id = r.text

    try:
        os.makedirs("~/.plugin")
    except OSError:
        pass

    with open("~/.plugin/client_id", "w+") as f:
        f.write(client_id)
