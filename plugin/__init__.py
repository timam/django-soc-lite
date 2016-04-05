import os


settings_directory = os.path.join(
    os.path.expanduser("~"), ".python_threat_plugin"
)


try:
    with open(os.path.join(settings_directory, "client_id")) as f:
        client_id = f.read()
    with open(os.path.join(settings_directory, "server")) as f:
        server, port = f.read().split(":")
except FileNotFoundError:
    client_id = None
    server = None
    port = None
