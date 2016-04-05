import os


settings_directory = os.path.join(
    os.path.expanduser("~"), ".python_threat_plugin"
)


class PluginNotConfiguredError(Exception):
    pass


try:
    with open(os.path.join(settings_directory, "client_id")) as f:
        client_id = f.read()
    with open(os.path.join(settings_directory, "server")) as f:
        server, port = f.read().split(":")
except FileNotFoundError:
    raise PluginNotConfiguredError("Please configure the plugin")
