from ats.topology import Testbed
from ats.topology import loader
from ats import aetest


def host_ip (testbed,device) :
    tb = testbed
    d = tb.devices[device]
    host_ip = d.connections.a.ip
    return str(host_ip)

def username(testbed,device) :
    tb = testbed
    d = tb.devices[device]
    username= d.tacacs.username
    return username

def password(testbed,device) :
    tb = testbed
    d = tb.devices[device]
    password=d.passwords.tacacs
    return password

############*****************Dont modify the lines below**************##################
def prompt(name) :
    prompt = name + '# '
    return prompt
    
def prompt_conf(name) :
    prompt_conf = name+'\(config\)# '
    return prompt_conf

def prompt_conf_ext(name) :
    prompt_conf_ext = name+'\(config[\-a-z]*\)# '
    return prompt_conf_ext
    
def prompt_xmlin(name) :
    # hostprompt=hostprompt()
    prompt_xmlin = name+'\(xmlin\)# '
    return prompt_xmlin
    
def prompt_xmlin_conf(name) :
    # hostprompt=hostprompt()
    prompt_xmlin_conf = name+'\(config\)\(xmlin\)# '
    return prompt_xmlin_conf

def prompt_xmlin_conf_ext(name) :
    # hostprompt=hostprompt()
    prompt_xmlin_conf_ext = name+'\(config[\-a-z]*\)\(xmlin\)# '
    return prompt_xmlin_conf_ext