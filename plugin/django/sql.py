from django.db import connection

def user_contacts(request):
    user = request.GET['username']
    sql = "SELECT * FROM user_contacts WHERE username = %s"
    cursor = connection.cursor()
    c = connection.cursor()
try:
    c.execute(sql, [user])
finally:
    c.close()
  