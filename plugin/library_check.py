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
	print result	
    else:
	print('alredy latest')
else:
    print("not need to update")	    
 
