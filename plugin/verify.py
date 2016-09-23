
class Client_Verify(object):
    def __init__(self, os):
        self.os = os

    def check(self):
        location = self.os.getcwd()
        filename = self.os.path.join(location, 'threat.ini')
        try:
            with open(filename, "r") as ins:
                array = []
                for line in ins:
                    line = line.rstrip('\n').rstrip('\r') 
                    array.append(line) 
        except IOError as exc:
            return False
        for i in range(len(array)):
            array[i] = array[i].replace(" ", "")
            array[i] = array[i].split("=")

        key = array[0][1]
        secret = array[1][1]
        
        return verify(key,secret)


def verify(k, s):
    registered_key = '1a8ccb91-7b1f-47ac-8a26-b84106f10037'
    registered_secret = 'a0ca4263-da57-45f5-aabb-b72e5a78b510'  
    if str(k) == str(registered_key) and str(s) == str(registered_secret):
        return True
    else:
        return False 
  

