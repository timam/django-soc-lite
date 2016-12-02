Version
=================
##v0.0.1

Installing
=================
Download `python_plugin.tar.gz` file from dashboard

##with ``pip``::

    . Activate your project's `virtualenv`
    
    . Go to `python_plugin.tar.gz` contains directory
    
    $ pip install python_plugin.tar.gz

##with ``python setup``::

    . Activate your project's `virtualenv`
    
    . Extract `python_plugin.tar.gz`
    
    $ cd python_plugin/
    
    $ python setup.py install
 

Configure to Your APP
=================

    . Add  `plugin` to your project's `INSTALLED_APPS` in`settings.py` file.
    
    . Add the following middleware to your project's `MIDDLEWARE_CLASSES` in `settings.py` file:
    
      ``'plugin.django.middleware.ThreatEquationMiddleware',``
      
      
Configure ``threat.ini`` (important)
================= 

    . Create ``threat.ini`` file in your Home directory.
    .Ex:
         In Apache the directory will be `/var/www/threat.ini`
         In Ubuntu the directory will be `/home/<user>/threat.ini` 
    
    . Open `threat.ini` and update this file as below.
         id = <your id_key>
         secret = <your secret_key>



