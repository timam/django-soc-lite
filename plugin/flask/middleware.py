from flask import session,request
from plugin_flask.compat import iteritems
class FlaskMiddleware(object):

    def __init__(self,app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app): 
        for k, v in iteritems(self._default_config(app)):
            app.config.setdefault(k, v)
          
        app.before_request(self.process_request)
 
    def _default_config(self, app):
        return {
            'DEBUG_TB_HOSTS': (),
        }
       
    def process_request(self):
        request.form = request.form.copy()
        l = [k for k in request.form]
        if not l:
            return 
        par = l[0] 
        value = request.form.get(par)
        #print par,value
        re = True
        if re:
           request.form[par]='green'

        #print request.environ.get('HTTP_USER_AGENT')

   
    
   
 