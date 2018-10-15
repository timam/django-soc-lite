# django-soc-lite #

* A security middleware for Django app to Detect OWASP Top Basic and generate report in your dashboard


##with ``pip``::

    . Activate your project's `virtualenv`
    
    $ pip install django-soc-lite


Configure to Your APP
=================

    . Add  `django_soc_lite` to your project's `INSTALLED_APPS` in`settings.py` file.
    
    . Add the following middleware to your project's `MIDDLEWARE_CLASSES` in `settings.py` file:
    
      ``'django_soc_lite.threat.middleware.ThreatEquationMiddleware',``
      
      
Configure ``threat.ini`` (important)
================= 

    . Create ``threat.ini`` file in your Home directory.
    .Ex:
         In Apache the directory will be `/var/www/threat.ini`
         In Ubuntu the directory will be `/home/<user>/threat.ini` 
    
    . Open `threat.ini` and update this file as below.
         id = <your id_key>
         secret = <your secret_key>


## Features ##

1. SQL injection Attack
3. XSS Attack
4. Insecure File Access


### Who do I talk to? ###

* contact@threatequation.com