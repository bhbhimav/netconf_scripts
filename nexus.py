from ats.topology import Testbed
from ats.topology import loader	
from host import *
import re, time
import nxos_XML_errors 

######### logger #############
import os
import sys
import logging

logger = logging.getLogger(__name__)
LOGLEVEL = logging.DEBUG
logger.setLevel(LOGLEVEL)

################ end of logger###################

# gets xmlin output from the device_name for either edit-config or get types
def nxos_xmlin(device,device_name,cmd,type):
    d=device
    d.transmit('xmlin\r')
    d.receive(prompt_xmlin(device_name),timeout=50)
    if type== 'get' :
        d.transmit(cmd+'\r')
        d.receive(prompt_xmlin(device_name))
        out = d.receive_buffer()
    elif type == 'edit-config' :
        cmd_list = cmd.split('\n')
        d.transmit('config\r')
        d.receive(prompt_xmlin_conf(device_name))
        for i in range(len(cmd_list)) :
            d.transmit(cmd_list[i]+'\r')
            d.receive(prompt_conf_ext(device_name))
        d.transmit('end\r')
        d.receive(prompt_xmlin(device_name))
        out = d.receive_buffer()
    d.transmit('exit\r')
    d.receive(prompt(device_name))
    out_list = out.split('\n')
    for line in range(len(out_list)) :
        if out_list[line] == ']]>]]>\r' :
            end_line = line
    for i in range(len(out_list)) :
        matchobj=re.match("(\s*[\A-Za-z0-9-./:_\?\"=<> ]*)",out_list[i])
        out_list[i]=matchobj.group(1)
    start = "<?xml version=\"1.0\"?>"
    for line in range(len(out_list)) :
        if out_list[line] == start :
            start_line = line
    return_list = out_list[start_line:end_line]
    
    out = "\n".join(return_list)
    return out

def initial_setup(device):
   
    nxos_exec(device,'terminal length 0')
    nxos_exec(device,'terminal width 511')
    nxos_exec(device,'terminal session-timeout 0')
    nxos_exec(device,'clear logging logfile')
    nxos_exec(device,'clear cores')
    nxos_exec(device,'show version')
    

#executes a command in nexus switch 
def nxos_exec(device,cmd) :
    output=device.execute(cmd)
    return output

#config a given command or various commands from the file (if file option is not required send it as 0 
def nxos_config(device,conf,file=1) :

    d=device
    if file ==1 :
        f = open(conf, 'r')
        cmd_list=f.read() 
        f.close()        
        config_list = cmd_list.split('\n')
        d.config(cmd_list)
    else :
        d.config(conf)

#given a config file  it appends no to the commands and unconfigures the commands 
def nxos_unconfig(device,unconfig_file) :
    d=device

    f = open(unconfig_file, 'r')
    cmd_list=f.read()
    config_list = cmd_list.split('\n')
    for line in range(len(config_list)) :
        unconfig_send = 'no ' + config_list[line]
        d.config(unconfig_send)

    f.close()
    
# verifies if the config with default operation of merge or none is applied on switch or not 
# permitted inputs for default_op is 'none' or 'merge'
def verify_default_op(device,config,default_op) :
    
    d=device

    config_list_send = []
    output = []
    return_count =0
    config_list =  config.split('\n')
    logger.info ('received config list is %s' %str(config_list))

    for i in range(len(config_list)) :
        matchobj=re.match("\s*([A-Za-z0-9-./ ]*)",config_list[i])
        config_list[i]=matchobj.group(1) 
    i=0 
    for i in range(len(config_list)) :
        config_list_send.append('show running-config '+' | grep \\"' + config_list[i] +'\\"')
    for line in range(len(config_list_send)) :
        out=d.execute(config_list_send[line])
        output.append(out)
    line = 0
    for i in range(len(output)) :
        matchobj=re.match("\s*([A-Za-z0-9-./ ]*)",output[i])
        output[i]=matchobj.group(1)   
        
    if default_op ==  "merge":
        while line < len(output) :
            try :
                if config_list[line] == output[line] :
                    pass
                else :
                    return_count +=1
                    logger.debug ("the command that is not matching is %s" %config_list[line])
                    raise nxos_XML_errors.RunConfigError
            finally :    
                line = line+1 
    elif default_op ==  "none":
        while line < len(output) :
            try :
                if not config_list[line] == output[line] :
                    pass
                else :
                    return_count += 1
                    logger.debug ("the command that is not matching is %s" %config_list[line])
                    raise nxos_XML_errors.RunConfigError
            finally :
                line = line+1 
    if return_count == 0 :
        return 1
    else :
        logger.debug ("%s config lines are mismatching from the expected" %return_count)
        return 0 

# verifies operation in edit-config for various config
# need to send the config to be checked as dictionary. position to be mentioned is the __XML__PARAM number in the order 
# for example if there is a command "vlan 10" for which the corresponding __XML__PARAM is 2nd __XML__PARAM field from top of request then 
# send dictionary as {'2':'vlan 10'}
def verify_op(device,config,**kwargs):
    
    d=device
    merge_list = []
    delete_list = []
    merge_list_send = []
    delete_list_send = []
    merge_output = []
    delete_output = []
    return_count=0
    
    config_list = config.split('\n')

    for i in range(len(config_list)) :
        matchobj=re.match("\s*([A-Za-z0-9-./ ]*)",config_list[i])
        config_list[i]=matchobj.group(1) 
    for k,v in kwargs.iteritems() :
        if kwargs[k] == "merge" or kwargs[k] == "create" :
            merge_list.append(k)
        elif kwargs[k] == "delete" :
            delete_list.append(k)
 
    #checking if the merge commands have merged in the switch
    if len(merge_list) > 0 :
        for i in range(len(merge_list)) :
            merge_list_send.append('show running-config '+' | grep word-exp \\"' + config_list[(int(merge_list[i]))-1] +'\\"')
        for line in range(len(merge_list_send)) :
            out=d.execute(merge_list_send[line])
            merge_output.append(out)
        line = 0
        for i in range(len(merge_output)) :
            matchobj=re.match("\s*([A-Za-z0-9-./ ]*)",merge_output[i])
            merge_output[i]=matchobj.group(1)
        
        while line < len(merge_output) :
            try :
                if config_list[int(merge_list[line])-1] == merge_output[line] :
                    pass
                else :
                    return_count=return_count+1
                    logger.debug ("the command that is not matching is %s" %config_list[line])
                    raise nxos_XML_errors.RunConfigError
            finally :
                line = line+1
               
    #checking if the delete commands have been deleted from the switch
    if len(delete_list) > 0 :
        for i in range(len(delete_list)) :
            delete_list_send.append('show running-config '+' | grep word-exp \\"' + config_list[(int(delete_list[i]))-1] +'\\"')
        for line in range(len(delete_list_send)) :
            out=d.execute(delete_list_send[line])
            delete_output.append(out)

        for i in range(len(delete_output)) :
            matchobj=re.match("\s*([A-Za-z0-9-./ ]*)",delete_output[i])
            delete_output[i]=matchobj.group(1)
        line = 0  
        while line < len(delete_output) :
            try :
                if not config_list[int(delete_list[line])-1] == delete_output[line] :
                    pass
                else :  
                    return_count = return_count+1
                    logger.debug ("the command that is not matching is %s" %config_list[line])
                    raise nxos_XML_errors.RunConfigError
            finally :
                line = line+1
    if return_count == 0 :
        return 1
    else :
        logger.debug ("%s config lines are mismatching from the expected" %return_count)
        return 0 

#this proc verifies if the config sent with error-option is configured as expected or not
# the config which is sent has to be passed to this along with the error-option and error position        
# for example if errored command is there at 2nd position in config the args should be [2]
def verify_error(device,config,option,*args) :
    cmd_list = config.split('\n')
    add_list=[]
    remove_list = []
    match_out = []
    delete_out = []
    return_count=0

    d=device
     
    for i in range(len(cmd_list)) :
        matchobj=re.match("\s*([A-Za-z0-9-./ ]*)",cmd_list[i])
        cmd_list[i]=matchobj.group(1)
        
    #this creates lists with commands that has to be configured or removed based upon error-option
    if option == 'continue' :
        for k in args :
            remove_list.append(cmd_list[int(k)-1])
        for line in range(len(remove_list)) :
            cmd_list.remove(remove_list[line])
        add_list = cmd_list
    elif option == 'stop' :
        remove_list = cmd_list[int(args[0])-1:len(cmd_list)]
        add_list = cmd_list[0:int(args[0])-1]
    elif option == 'rollback' :
        remove_list = cmd_list
        add_list = []
    
    # this gets the device output for the commands that has to be configured
    for line in range(len(add_list)) :
        send_line = 'show running-config '+'| grep word-exp \\"' + add_list[line] +'\\"'
        output = d.execute(send_line)
        match_out.append(output)
    for i in range(len(match_out)) :
        matchobj=re.match("\s*([A-Za-z0-9-./ ]*)",match_out[i])
        match_out[i]=matchobj.group(1)
    
    # this gets the device output for the commands that has to be removed    
    for line in range(len(remove_list)) :
        send_line = 'show running-config '+'| grep word-exp \\"' + remove_list[line] +'\\"'
        output = d.execute(send_line)
        delete_out.append(output)
    for i in range(len(delete_out)) :
        matchobj=re.match("\s*([A-Za-z0-9-./ ]*)",delete_out[i])
        delete_out[i]=matchobj.group(1)
   
    #this compares the device output to the expected output for the commands that has to be configured on device 
    line = 0  
    while line < len(match_out) :
            try :
                if match_out[line] == add_list[line] :
                    pass
                else :  
                    return_count = return_count+1
                    logger.debug ("the command that is not matching is %s" %add_list[line])
                    raise nxos_XML_errors.RunConfigError
            finally :
                line = line+1
    
    #this compares the device output to the expected output for the commands that has to be removed from device 
    line = 0  
    while line < len(delete_out) :
            try :
                if delete_out[line] == '' :
                    pass
                else :  
                    return_count = return_count+1
                    logger.debug ("the command that is not matching is %s" %remove_list[line])
                    raise nxos_XML_errors.RunConfigError
            finally :
                line = line+1            
    
    if return_count == 0 :
        return 1
    else :
        logger.debug ("%s config lines are mismatching from the expected" %return_count)
        return 0 

def check_run(device,file,rollback):

    d=device
    if rollback == 1 :
        source = file 
        send_line = 'show file ' + source 
        source_output = d.execute(send_line)
        target = 'running-config'
        send_line = 'show ' + target
        target_output=d.execute(send_line)
    else :
        source = 'running-config'
        send_line = 'show ' + source
        source_output = d.execute(send_line)
        target = file 
        send_line = 'show' + file
        target_output = d.execute(send_line)
    source_list = source_output.split('\n')
    target_list = target_output.split('\n')
    
    for i in range(len(source_list)) :
            matchobj=re.match("\s*([A-Za-z0-9-./ ]*)",source_list[i])
            source_list[i]=matchobj.group(1)
            
    for i in range(len(target_list)) :
            matchobj=re.match("\s*([A-Za-z0-9-./ ]*)",target_list[i])
            target_list[i]=matchobj.group(1)

# enables netconf syslogs on switch           
def netconf_syslog(device) :
    config = '''logging monitor 7
                logging logfile messages 7'''
    cmd1 = 'debug xml server session all logging level 7'
    cmd2 = 'clear logging logfile'
    device.execute(cmd1)
    device.execute(cmd2)
    device.config(config) 

def copy_file (testbed,device,filename):
    tb = testbed
    d=device
    tftp_server = tb.servers['tftp']
    tftp_address = tftp_server.address
    tftp_username = tftp_server.username
    tftp_password = tftp_server.password
    copy_cmd = 'copy '+'scp://'+tftp_address+filename+' bootflash: vrf management'
    d.transmit(copy_cmd+'\r')
    if d.receive(r'Warning: There is already a file existing with this name. Do you want to overwrite') :
        d.transmit('y\r')
    d.receive('Enter username: ')
    d.transmit(tftp_username+'\r')
    if d.receive(r'The authenticity of host '):
        d.transmit('yes\r')
    d.receive(r'password: ')
    d.transmit(tftp_password+'\r')
    time.sleep(20)
   
if __name__=='__main__' :
    tb = loader.load('auto_brk_anchinch.yaml')
    device_name = 'bgl-n7k'
    d = tb.devices[device_name]
    d.connect()
    cmd = '''vlan 2121
            interface port-channel 2121'''
    nxos_xmlin(d,'JARVIS-2',cmd,'edit-config')