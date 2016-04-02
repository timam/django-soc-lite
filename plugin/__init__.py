import os


settings_directory = os.path.join(
    os.path.expanduser("~"), ".python_thread_plugin"
)

try:
    with open(os.path.join(settings_directory, "client_id")) as f:
        client_id = f.read()
except FileNotFoundError:
    client_id = None
