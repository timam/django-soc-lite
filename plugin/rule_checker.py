import os.path
import json
import re

def sql_replace(q):
    for item in get_rule():
        tag = item['tags']['tag'][0]
        if  tag == 'sqli':
            rules = item['rule']
            regex = re.compile(rules)
            if regex.search(q):
                q = regex.sub('',q)

    return q

def get_rule():
    BASE = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(BASE,'rules.json'),'r') as f:
        data = json.load(f)
    return data  

def converter(q):
    try:
        from plugin import url_coder  
    except ImportError:
        import url_coder
    q = url_coder.decoder(str(q))
    return q


def xss_filter(q):
    q = converter(q)
    f = 0
    for item in get_rule():
        tag = item['tags']['tag'][0]
        if  tag == 'xss' or tag == 'dos':
            rules = item['rule']
            regex = re.compile(rules)
            if regex.search(q):
                f = 1

    if f == 0:
        return False
    return True    

def sql_filter(q):
    q = converter(q)
    f = 0
    for item in get_rule():
        tag = item['tags']['tag'][0]
        if  tag == 'sqli':
            rule = item['rule']
            regex = re.compile(rule)
            if regex.search(q):
                f = 1
            
    if f == 0:
        return False
    return True 

def id_filter(q):
    q = converter(q)
    f = 0
    for item in get_rule():
        tag = item['tags']['tag'][0]
        if  tag == 'id':
            rule = item['rule']
            regex = re.compile(rule)
            if regex.search(q):
                f = 1
            
    if f == 0:
        return False
    return True

def dt_filter(q):
    q = converter(q)
    f = 0
    for item in get_rule():
        tag = item['tags']['tag'][0]
        if  tag == 'dt' or tag == 'files':
            rule = item['rule']
            regex = re.compile(rule)
            if regex.search(q):
                f = 1
            
    if f == 0:
        return False
    return True 

def lfi_filter(q):
    q = converter(q)
    f = 0
    for item in get_rule():
        tag = item['tags']['tag'][0]
        if  tag == 'lfi':
            rule = item['rule']
            regex = re.compile(rule)
            if regex.search(q):
                f = 1
            
    if f == 0:
        return False
    return True

def rfe_filter(q):
    q = converter(q)
    f = 0
    for item in get_rule():
        tag = item['tags']['tag'][0]
        if  tag == 'rfe':
            rule = item['rule']
            regex = re.compile(rule)
            if regex.search(q):
                f = 1
            
    if f == 0:
        return False
    return True



def format_string_filter(q):
    q = converter(q)
    f = 0
    for item in get_rule():
        tag = item['tags']['tag'][0]
        if  tag == 'format string':
            rule = item['rule']
            regex = re.compile(rule)
            if regex.search(q):
                f = 1
    if f == 0:
        return False
    return True
    
#q = """O:3:%22foo%22:2:{s:4:%22file%22;s:9:%22shell.php%22;s:4:%22data%22;s:5:%22aaaa%22;}""" 
#print(xss_filter(str(q)))

  
