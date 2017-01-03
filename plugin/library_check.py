import os
BASE = os.path.dirname(os.path.abspath(__file__))
def checker(packages):
    """return True if any change in packages"""
    with open(os.path.join(BASE, 'library.txt'), 'r') as package_last:
        package_old = package_last.read()
    if str(package_old) != str(packages):
        return True    
    return False

def update_latest(packages):
    """update latest package list by updated one"""
    with open(os.path.join(BASE, 'library.txt'), 'w') as package_last:
        package_last.write(str(packages))

def system_check():
    """send log to server if any change in package within 12 hours"""
    import time
    modified_time = os.stat(os.path.join(BASE, 'library.txt')).st_mtime
    present_time = time.time() - (60)
    interval = (time.time() - modified_time) / 60
    if interval <= 720: #12 hours
        import pip
        package_list = pip.get_installed_distributions()
        if checker(package_list):
            update_latest(package_list)
            from safety import safety
            result = safety.check(package_list)
            data = {item.name:{'name':item.name,'current':item.version,'require':item.spec, 'data':item.data} for item in result}	
            import logging
            from plugin import client_id, plugin_name
            from datetime import datetime
            from plugin.system_logger import log	    
            logging.info(log(clientId=client_id, timestamp=str(datetime.utcnow()),ApplicationName=plugin_name, data=data))
            print(data)
        else:
            pass
    else:
        pass	    
 
