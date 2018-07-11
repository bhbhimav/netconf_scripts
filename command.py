import logging
import re
import host
import nexus
import nxos_XML_errors
import ncssh
import xml.etree.ElementTree as ET
from ats.topology import loader 
from xml import etree

#reads commands from the file and returns them
def cmd_req(req_type,file):
    if req_type == 'edit-config' or req_type == "default-operation" :
        f = open(file, 'r')
        cmd_list=f.read()
    elif req_type == 'get' :
        f = open(file, 'r')
        cmd_list=f.read()
    f.close()
    return cmd_list

# parses the edit config and adds default operation to it 
def parse_req_default (request_inp,request_type,request_option) :
    default_op_prefix = "<nf:default-operation>"
    default_op_suffix = "</nf:default-operation>"
    req_list=request_inp.split('\n')
    if request_type == "default-operation" :
        req_list.insert(6,default_op_prefix+request_option+default_op_suffix)
    str = "\n"
    parsed_req=str.join(req_list)
    return parsed_req

# parses the edit config request and adds operation at mentioned places to the request. 
#The operations has to be mentioned in a dictionary format with position and the operation to be added

def parse_req_op (request_in,**kwargs) :
    request_list = request_in.split('\n')
    param_list =[]
    count = 0
    for line in range(len(request_list)) :
        if re.match('\s*<[a-z0-9:]*__XML__PARAM__',request_list[line]) :
            param_list.append(line)
            count=count+1
    for key, value in kwargs.iteritems():
        param=re.match('(\s*<[a-z0-9:]*__XML__PARAM__[a-z-_]*)>',request_list[param_list[int(key)-1]])
        param_line=param.group(1)
        request_list[param_list[int(key)-1]]=param_line+' operation="'+value+'">'
        
    request_out = "\n".join(request_list)
    return request_out

# build a netconf validate request against the required filename in the file field of the request
def validate_req (filename='none',source='file') :
    
    if source == 'file' :
        validate_prefix = '''<?xml version="1.0"?>
            <rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <validate>
            <source>
            <url>'''
        
        validate_suffix ='''</url>
            </source>
            </validate>
            </rpc>'''
        request = validate_prefix+filename+validate_suffix
    elif source =='candidate' :
        request = '''<?xml version="1.0"?>
            <rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <validate>
            <source>
            <candidate/>
            </source>
            </validate>
            </rpc>'''
    
    return request

# builds a netconf lock request with the mentioned target to be locked 
def lock_request (target) :
	lock_req = '''<?xml version="1.0"?>
        <nf:rpc xmlns:nf="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
        <nf:lock>
        <nf:target>
        <nf:%s/>
        </nf:target>
        </nf:lock>
        </nf:rpc>'''
	lock_response = lock_req %(target)
	return lock_response

#builds a netconf unlock request with the mentioned target to be unlocked 	
def unlock_request (target) :
	unlock_req = '''<?xml version="1.0"?>
        <nf:rpc xmlns:nf="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
        <nf:unlock>
        <nf:target>
        <nf:%s/>
        </nf:target>
        </nf:unlock>
        </nf:rpc>'''
	unlock_response = unlock_req %(target)
	return unlock_response

# builds a netconf request to kill the netconf sesssion with given session-id    
def kill_session(sessionid) :
    kill_request='''<?xml version="1.0"?>
            <nf:rpc xmlns:nf="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns="http://www.cisco.com/nxos:7.2.0.D1.1.:nxos_operations" message-id="1">
            <nf:kill-session>
            <nf:session-id>%s</nf:session-id>
            </nf:kill-session>
            </nf:rpc>'''

    kill_message = kill_request %(sessionid)
    return kill_message

# build netconf copy config request from the given source and target    
def copy_config(source_first,rollback,source,target) :
    copy_config_prefix = '''<?xml version="1.0"?>
        <rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
        <copy-config>'''

    copy_config_suffix= '''
    </copy-config>
        </rpc>
        '''
    
    if source_first == 1 :
        if rollback == 1 :
            copy_config_message = '''
            <source>
                    <url>file://%s</url>
            </source>
            <target>
                    <%s/>
            </target>'''
            
        else :              
            copy_config_message = '''
            <source>
                    <%s/>
            </source>
            <target>
                    <url>file://%s</url>
            </target>'''
        copy_config_req = copy_config_prefix + copy_config_message %(source,target) + copy_config_suffix
    else :
        if rollback == 1 :
            copy_config_message = '''
            <target>
                    <%s/>
            </target>
            <source>
                    <url>file://%s</url>
            </source>'''
        else :  
            copy_config_message = '''
            <target>
                    <url>file://%s</url>
            </target>
            <source>
                    <%s/>
            </source>'''
        copy_config_req = copy_config_prefix + copy_config_message %(target,source) + copy_config_suffix
    return copy_config_req

# build netconf edit-config request with test-option field added to it 
def test_option(req,option) :
    test_op_prefix = "<nf:test-option>"
    test_op_suffix = "</nf:test-option>"
    req_list=req.split('\n')
    req_list.insert(6,test_op_prefix+option+test_op_suffix)
    str = "\n"
    parsed_req=str.join(req_list)
    return parsed_req

#build netconf edit-config request with error-option field  added to it 
def error_option(req,option) :

    error_op_prefix = "<nf:error-option>"
    error_op_suffix = "</nf:error-option>"
    req_list=req.split('\n')
    req_list.insert(6,error_op_prefix+option+error_op_suffix)
    str = "\n"
    parsed_req=str.join(req_list)
    return parsed_req

# injects error into netconf edit-config request  and returns the errored request
def build_error(req,**kwargs) :
    
    request_list = req.split('\n')
    param_list =[]
    count = 0
    for line in range(len(request_list)) :
        if re.match('\s*<[a-z0-9:]*__XML__value',request_list[line]) :
            param_list.append(line)
            count=count+1
    print param_list
    for key,value in kwargs.iteritems():
        print request_list[param_list[int(key)-1]]
        new_line=re.match('(\s*[0-9a-z<:]*__XML__value>)[0-9a-z:]+([0-9a-z</:]*__XML__value>)',request_list[param_list[int(key)-1]])
        request_list[param_list[int(key)-1]]=new_line.group(1)+value+new_line.group(2)

    request_out = "\n".join(request_list)
    return request_out
    
#verifies if the output from Netconf GET is a valid output or not
def verify_show(response) :
    response = ncssh._stripdelim(response)
    response_list = response.split('\n')
    read_start = 0
    read_end = 0
    for i in range(len(response_list)) :    
        if re.search('<[0-9a-z:]*__readonly__>',response_list[i]) :
            read_start += 1        
        if re.search('\S*</[0-9a-z:]*__readonly__>',response_list[i]):
            read_end += 1
    if read_start == 1 and read_end == 1 :
        logging.info ('No error in the get response')
        pass 
    else :
        logging.error ('expected output is not returned in get response')
        raise nxos_XML_errors.ShowError 
    
#gets the edit-config request and replaces the edit-config with validate to check if the config is valid or not
def validate_edit(req):
    req_list = req.split('\n')
    for line in range(len(req_list)) :
        if re.match('\s*<nf:edit-config>\s*',req_list[line]):
            out = re.match('(\s*)<nf:edit-config>(\s*)',req_list[line])
            config_start = line
            start_space = out.group(1)
            end_space = out.group(2)
        if re.match('\s*</nf:edit-config>\s*',req_list[line]):
            config_end = line
    req_list[config_start] = start_space+'<nf:validate>'+end_space
    req_list[config_end] = start_space+'</nf:validate>'+end_space
    for line in range(len(req_list)) :
        if re.match('\s*<nf:target>\s*',req_list[line]) :
            out = re.match('(\s*)<nf:target>(\s*)',req_list[line])
            target_start = line
        if re.match('\s*<nf:target>\s*',req_list[line]) :
            target_end = line
    del req_list[target_start+1]
    del req_list[target_end]
    req_list[target_start]=out.group(1)+'<nf:source>'+out.group(2)
    source_end = out.group(1)+'</nf:source>'+out.group(2)
    req_list.insert(config_end-2,source_end)

    request_out = "\n".join(req_list)
    return request_out

#builds candidate config request for given edit-config request
def build_candidate(req):
    req_list = req.split("\n")

    for line in range(len(req_list)):
        if re.match('\s*<nf:target>\s*',req_list[line]):
            out = re.match('(\s*[<a-z]+:)[a-z]+([/>]+\s*)',req_list[line+1])
            req_list[line+1] = out.group(1)+"candidate"+out.group(2)

    request_out = "\n".join(req_list)
    return request_out

#returns candidate commit request for candidate config
def build_candidate_commit():
    response = '''<?xml version="1.0"?>
    <nf:rpc xmlns:nf="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="222">
        <nf:commit/>
    </nf:rpc>'''
    return response

#returns discard-changes request for candidate config
def build_candidate_discard():
    response = '''<?xml version="1.0"?>
    <nf:rpc xmlns:nf="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
        <nf:discard-changes/>
    </nf:rpc>'''
    return response

#builds edit config request with url as source for config 
def edit_config_url(device,device_name,filename,file=1,operation ='default',test_option='none',error_option='none'):
    response=nexus.nxos_xmlin(device,device_name,'','edit-config')
    response_list = response.split('\n')
    
    for line in range(len(response_list)) :
        if re.search('<nf:config>',response_list[line]) :
            space=re.match('(\s+)<nf:config>',response_list[line])
            config_start = line
    
    if not operation == 'default' and not test_option == 'none' and not error_option == 'none' :
        response_list.insert(config_start,space.group(1)+'<nf:default-operation>'+ operation + '</nf:default-operation>')
        response_list.insert(config_start+1,space.group(1)+'<nf:test-option>' + test_option +'</nf:test-option>')
        response_list.insert(config_start+1,space.group(1)+'<nf:test-option>' + test_option +'</nf:test-option>')

    elif not operation == 'default' and not test_option == 'none' :
        response_list.insert(config_start,space.group(1)+'<nf:default-operation>'+ operation + '</nf:default-operation>')
        response_list.insert(config_start+1, space.group(1)+'<nf:test-option>' + test_option +'</nf:test-option>')
    
    elif not operation == 'default' and not error_option == 'none' :
        response_list.insert(config_start,space.group(1)+'<nf:default-operation>'+ operation + '</nf:default-operation>')
        response_list.insert(config_start+1,space.group(1)+'<nf:error-option>' + error_option +'</nf:error-option>')

    elif not test_option == 'none' and not error_option == 'none' :
        response_list.insert(config_start,space.group(1)+'<nf:test-option>' + test_option +'</nf:test-option>')
        response_list.insert(config_start+1,space.group(1)+'<nf:error-option>' + error_option +'</nf:error-option>')
    
    elif not operation == 'default' :
        response_list.insert(config_start,space.group(1)+'<nf:default-operation>'+ operation + '</nf:default-operation>')

    elif not test_option == 'none' :
        response_list.insert(config_start,space.group(1)+'<nf:test-option>' + test_option +'</nf:test-option>')

    elif not error_option == 'none' :
        response_list.insert(config_start,space.group(1)+'<nf:error-option>' + error_option +'</nf:error-option>')
    
    print response_list
    for line in range(len(response_list)) :
        if re.search('<nf:config>',response_list[line]) :
            space=re.match('(\s+)<nf:config>',response_list[line])
            config_start = line

    if file == 1 :
        response_list[config_start+1] = space.group(1)+'    <url>file://'+filename+'</url>'
    else :
        response_list[config_start+1] = space.group(1)+'    <url>'+filename+'</url>'

    response_out = "\n".join(response_list)
    return response_out

# gives request for copy config from candidate to file or vice-versa. 
# rollback is 0,1 for copy from file to candidate and candidate to file respectively
def copy_config_candidate(filename,rollback) :
    copy_config_prefix = '''<?xml version="1.0"?>
        <rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
        <copy-config>'''

    copy_config_suffix= '''</copy-config>
        </rpc>'''
    
    if rollback == 0 :
        copy_config_message = '''
            <target>
                    <candidate/>
            </target>
            <source>
                <url>%s</url>
            </source>'''
    elif rollback == 1 :
        copy_config_message = '''
            <target>
                <url>%s</url>
            </target>
            <source>
                <candidate/> 
            </source>'''
    copy_config_req = copy_config_prefix + copy_config_message %(filename) + copy_config_suffix
    return copy_config_req

#returns confirmed commit request for with specified timeout
def build_confirmed_commit(timeout=600):
    response = '''<?xml version="1.0"?>
    <nf:rpc xmlns:nf="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
        <nf:commit>
        <nf:confirmed/>
        <nf:confirm-timeout>%s</nf:confirm-timeout>
        </nf:commit>
    </nf:rpc>'''
    return response %(timeout)

def get_config_candidate(device,device_name):
    response = '''<?xml version= "1.0"?>
    <nf:rpc xmlns:nf="urn:ietf:params:xml:ns:netconf:base:1.0" message-id=" 1">
        <nf:get-config>
        <nf:source>
            <nf:candidate/>
        </nf:source>
        </nf:get-config>
    </nf:rpc>'''
    config_op = nexus.nxos_xmlin(device,device_name,'','edit-config')
    config_op_list = config_op.split('\n')
    response_list = response.split('\n')
    response_list[1] = config_op_list[1]
    response_out = "\n".join(response_list)
    return response_out

# verifies the get-config response against the response from the cli
def verify_get_config(device,command,response,candidate=0,candidate_commands='none') :
    
    cli_output = nexus.nxos_exec(device,command)
    cli_output_list = cli_output.split('\n')
    for line in range(len(cli_output_list)) :
        if re.search('version\s+[0-9.\(\)A-Z]+',cli_output_list[line]) :
            start_line = line
    cli_output_list = cli_output_list[start_line:len(cli_output_list)]

    response_list = response.split('\n')
    for line in range(len(response_list)) :
        if re.search('<nf:data>',response_list[line]) :
            start_line = line
        if re.search('</nf:data>',response_list[line]) :
            end_line = line
    response_list = response_list[start_line+1:end_line]
    
    for line in range(len(response_list)) :
        if re.search('version\s+[0-9.\(\)A-Z]+',response_list[line]) :
            start_line = line
    response_list = response_list[start_line:len(response_list)]

    if not candidate == 0 :
        for x in candidate_commands.split('\n') :
            cli_output_list.append(x)

    cli_output_list = [x.replace("\r","") for x in cli_output_list]
    cli_output_list = [x.lstrip() for x in cli_output_list]
    cli_output_list = [x.rstrip() for x in cli_output_list]
    
    response_list = [x.lstrip() for x in response_list]
    response_list = [x.rstrip() for x in response_list]

    for x in cli_output_list :
        if not x in response_list :
            logging.error('line that is not matching is %s' %x)
            raise nxos_XML_errors.GetConfigError
        else :
            pass

#creates netconf request with source as url and target as candidate
def candidate_url(device,device_name,source):
    response=nexus.nxos_xmlin(device,device_name,'','edit-config')
    req_list = response.split('\n')

    for line in range(len(req_list)) :
        if re.search('<nf:config>',req_list[line]) :
            space=re.match('(\s+)<nf:config>',req_list[line])
            config_start = line

    req_list[config_start+1] = space.group(1)+'    <url>file://'+source+'</url>'
    for line in range(len(req_list)):
        if re.match('\s*<nf:target>\s*',req_list[line]):
            out = re.match('(\s*[<a-z]+:)[a-z]+([/>]+\s*)',req_list[line+1])
            req_list[line+1] = out.group(1)+"candidate"+out.group(2)

    response_out = "\n".join(req_list)
    return response_out


#checks if batch replies in batch request are valid or not
def check_batch_process_response(response):
    response_list=response.split(']]>]]>')
    response_list = [x for x in response_list if x.strip()]
    for x in response_list :
        verify_show(x)

#creates batch request for several show commands into a single request by modifying namespaces
def create_batch_request(device,device_name,cmd):
    command_list = cmd.split('\n')
    command_number = len(command_list)
    response_list = []
    for cmd in command_list :
        response_list.append(nexus.nxos_xmlin(device,device_name,cmd,'get'))
    final_list = []
    suffix_list_final=[]
    response = response_list[0].split('\n')
    for line in range(len(response)) :
        if re.search('<nf:rpc',response[line]):
            ns_line = line
        if re.search('<show>',response[line]):
            show_start_line = line
        if re.search('</show>',response[line]):
            show_end_line = line
    namespace=re.match("(\s*<nf:rpc xmlns:nf=\"urn:ietf:params:xml:ns:netconf:base:1.0\"\s+)xmlns(=\"http:\/\/www.cisco.com\/[A-Za-z0-9.:_-]+\"\s+)(message-id=\"[0-9]+\">)",response[ns_line])
    namespace_line=namespace.group(1)+"xmlns:m"+str(1)+namespace.group(2)
    namespace_line_prefix = response[0]
    namespace_line_suffix = response[ns_line+1:show_start_line]
    suffix_list = response[show_start_line:show_end_line+1]
    for line in range(len(suffix_list)) :
        if re.search('<',suffix_list[line]) and re.search('</',suffix_list[line]):
            modified_line = suffix_list[line].replace('</','</m1:')
            modified_line = modified_line.replace('</','~').replace('<','<m1:').replace('~','</')
            suffix_list_final.append(modified_line)
        elif re.search('<',suffix_list[line]) and re.search('</',suffix_list[line])==None:
            suffix_list_final.append(suffix_list[line].replace('<','<m1:'))
        elif re.search('<',suffix_list[line])==None and re.search('</',suffix_list[line]):
            suffix_list_final.append(suffix_list[line].replace('</','</m1:'))
    end_list=response[show_end_line+1:len(response)]

    final_list.append(namespace_line_prefix)

    for num in range(len(response_list[1:len(response_list)])) :
        response = response_list[num+1].split('\n')
        for line in range(len(response)) :
            if re.search('<nf:rpc',response[line]):
                ns_line = line
            if re.search('<show>',response[line]):
                show_start_line = line
            if re.search('</show>',response[line]):
                show_end_line = line
        ns=re.match("(\s*<nf:rpc xmlns:nf=\"urn:ietf:params:xml:ns:netconf:base:1.0\"\s+)xmlns(=\"http:\/\/www.cisco.com\/[A-Za-z0-9.:_-]+\"\s+)message-id=\"[0-9]+\">",response[ns_line])
        namespace_line=namespace_line+' xmlns:m'+str(num+2)+ns.group(2)
        suffix_list = response[show_start_line:show_end_line+1]
        for line in range(len(suffix_list)):
            ns_open = '<m'+str(num+2)+":"
            ns_close = '</m'+str(num+2)+":"
            if re.search('<',suffix_list[line]) and re.search('</',suffix_list[line]):
                modified_line = suffix_list[line].replace('</',ns_close)
                modified_line = modified_line.replace('</','~').replace('<',ns_open).replace('~','</')
                suffix_list_final.append(modified_line) 
            elif re.search('<',suffix_list[line]) and re.search('</',suffix_list[line])==None:
                suffix_list_final.append(suffix_list[line].replace('<',ns_open))
            elif re.search('<',suffix_list[line])==None and re.search('</',suffix_list[line]) :
               suffix_list_final.append(suffix_list[line].replace('</',ns_close)) 
    namespace_line = namespace_line+namespace.group(3)

    final_list.append(namespace_line)
    final_list = final_list+namespace_line_suffix
    final_list = final_list+suffix_list_final
    final_list = final_list+end_list
    batch_request = '\n'.join(final_list)
    return batch_request

if __name__ == '__main__' :
    t = loader.load('auto_brk_anchinch.yaml')
    device = 'JARVIS-2'
    d= t.devices[device]
    d.connect()
    out=get_config_candidate(d,device)
    print out