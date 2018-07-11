#############################################################################
# Script Headear
# Netconf
#
# Purpose:
# Netconf performance testing
#
# Author:
# bhbhimav
#
# Maintainer:
# bhbhimav
#
# Description:
# tests various netconf features 
#
# Synopsis
#
# Pass/Fail Criteria:
#

from ats import aetest
from ats.results import *
import command
import ncssh
import host
import nexus
import logging 
import sys
import os,time
import re
import nxos_XML_errors
import string, random
import xml.etree.ElementTree as ET

logger=logging.getLogger(__name__)
LOGLEVEL = logging.INFO
logger.setLevel(LOGLEVEL)

global edit_config_dir
global show_cmd_dir

def get_edit_config_list():
	global edit_config_dir
	count=len([name for name in os.listdir(edit_config_dir) if os.path.isfile(os.path.join(edit_config_dir, name)) \
			and 'config' in name])
	return_list = []	
	x = 1	
	while x <= count:
		config_file=edit_config_dir+'config'+str(x)+'.txt'
		return_list.append(os.path.basename(config_file))
		x += 1
	return return_list

def get_show_cmd_list():
	global show_cmd_dir
	count=len([name for name in os.listdir(show_cmd_dir) if os.path.isfile(os.path.join(show_cmd_dir, name)) \
			and 'show' in name])
	return_list = []	
	x = 1	
	while x <= count:
		show_file=show_cmd_dir+'show'+str(x)+'.txt'
		return_list.append(os.path.basename(show_file))
		x += 1
	return return_list	

class common_setup(aetest.CommonSetup):

	logger.info('this is common setup')
		
	@aetest.subsection
	def connect_device(self,testbed,device):
		device=testbed.devices[device]
		logger.info('connecting to device %s'%device)
		global d
		d=device
		try :
			d.connect()
			int_value = Passed.code
			assert int_value == 1
		except ConnectionError:
			logger.error('device not connected')
			int_value = Failed.code
			assert int_value == 1
		except ConnectionRefusedError:
			logger.error('device not connected')
			int_value = Failed.code
			assert int_value == 1

	@aetest.subsection
	def device_setup(self):
		try :
			nexus.initial_setup(d)
			int_value = Passed.code
			assert int_value == 1
		except :
			int_value = Failed.code
			assert int_value == 1
	@aetest.subsection
	def enable_netconf_logs(self):
		try:
			nexus.netconf_syslog(d)
			logging.info ('enabled logging for netconf in switch')
			int_value = Passed.code
			assert int_value == 1
		except:
			int_value = Failed.code
			assert int_value == 1

	@aetest.subsection
	def cmd_list(self,edit_config_location,show_cmd_location):
		global edit_config_dir
		global show_cmd_dir
		edit_config_dir = edit_config_location
		show_cmd_dir = show_cmd_location


class syslog_netconf_initiated(aetest.Testcase):

    logging.info ('checks if syslog is generated after netconf session is initiated')
    @aetest.setup
    def setup(self,testbed,device):
        self.obj = object()
        syslog_netconf_initiated.testbed = testbed
        syslog_netconf_initiated.device = device
        syslog_netconf_initiated.nxos = ncssh.SshConnect(host.host_ip(syslog_netconf_initiated.testbed,syslog_netconf_initiated.device))
        try :
            nexus.netconf_syslog(d)
            logging.info ('enabled logging for netconf in switch')
            nexus.nxos_exec(d,'clear logging logfile')
            logging.info ('cleared logfile on switch')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def syslog_test(self):
        self.obj = object()
        try :
            sessionid=syslog_netconf_initiated.nxos.nc_sshconnect(username=host.username(syslog_netconf_initiated.testbed,syslog_netconf_initiated.device),password=host.password(syslog_netconf_initiated.testbed,syslog_netconf_initiated.device))
            logging.info ('session-id is %s' %(sessionid))
            send_line = 'show logging logfile | grep '+str(sessionid) + ' | grep \\"Hello sent\\"'
            output1=nexus.nxos_exec(d,send_line) 
            send_line = 'show logging logfile | grep '+str(sessionid) + ' | grep \\"got hello\\"'
            output2 = nexus.nxos_exec(d,send_line)

            if re.search ('XML sub agent log: Hello sent for session id',output1) and re.search ('XML sub agent log: process_hello: got hello for this SSH session id',output2) :
                logging.info ('Logs are present for the hello message exchange between switch and netconf with session id %s' %str(sessionid))
            else :
                logging.error ('log not available for hello messages exchange between switch and netconf client')
                int_value=Failed.code
                assert int_value == 1
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            int_value=Passed.code
            assert int_value == 1
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        finally :
            close_message = syslog_netconf_initiated.nxos.closesession() 
            int_value=Passed.code
            assert int_value == 1

class syslog_netconf_fail(aetest.Testcase):

    logging.info ('checks if syslog after netconf request fails')
    @aetest.setup
    def setup(self,testbed,device,error_file,config_file_dir,unconfig_file):
        self.obj = object()
        syslog_netconf_fail.testbed = testbed
        syslog_netconf_fail.device = device
        syslog_netconf_fail.nxos = ncssh.SshConnect(host.host_ip(syslog_netconf_fail.testbed,syslog_netconf_fail.device))

        #config file from which config has to be sent 
        config=error_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        syslog_netconf_fail.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        syslog_netconf_fail.unconfig_file=config_file_dir + unconfig_file
        
        try :
        	print syslog_netconf_fail.config
        	request = nexus.nxos_xmlin(d,syslog_netconf_fail.device,syslog_netconf_fail.config,'edit-config')
        	err_dict = {'6':'pending'}
        	syslog_netconf_fail.request = command.build_error(request,**err_dict)
        	int_value = Passed.code
        	assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def syslog_test(self):
        self.obj = object()
        try :
            sessionid=syslog_netconf_fail.nxos.nc_sshconnect(username=host.username(syslog_netconf_fail.testbed,syslog_netconf_fail.device),password=host.password(syslog_netconf_fail.testbed,syslog_netconf_fail.device))
            logging.info ('session-id is %s' %(sessionid))
            response =syslog_netconf_fail.nxos._send(syslog_netconf_fail.request,0)
            logging.info ('response is %s' % (response))
            time.sleep(10)
            send_line='sh logging logfile | grep RPC_ERROR | grep '+ str(sessionid)
            output = nexus.nxos_exec(d,send_line)
            match=re.search('reason:([0-9a-zA-z\' ]+)',output)

            if not match == 'None' :
                logging.info ('the reason for Netconf failure from syslog is %s'%match.group(1))
                error_string = ncssh._stripdelim(response)
                error_list = []
                root = ET.fromstring(error_string)
    
                error_type = root[0][0].text
                error_list.append(error_type)
    
                error_tag = root[0][1].text
                error_list.append(error_tag)      
    
                error_severity = root[0][2].text
                error_list.append(error_severity)
        
                error_message = root[0][3].text
                error_list.append(error_message)
                
                syslogerror = match.group(1)
                rpcerror=error_list[3].rstrip('\n')
                syslogerror=syslogerror.rstrip()

                if rpcerror == syslogerror  :
                    logging.info ('error from netconf reply and syslog matches')
                    int_value=Passed.code
                    assert int_value == 1
                else :
                    logging.error("error from netconf reply and syslog doesnt match")
                    int_value=Failed.code
                    assert int_value == 1 
            
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            int_value=Passed.code
            assert int_value == 1
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        finally :
            close_message = syslog_netconf_fail.nxos.closesession() 
            nexus.nxos_unconfig(d,syslog_netconf_fail.unconfig_file)
            int_value=Passed.code
            assert int_value == 1  

class syslog_netconf_success(aetest.Testcase):

    logging.info ('checks if syslog after netconf request succeeds')
    @aetest.setup
    def setup(self,testbed,device,config_file,config_file_dir,unconfig_file):
        self.obj = object()
        syslog_netconf_success.testbed = testbed
        syslog_netconf_success.device = device
        syslog_netconf_success.nxos = ncssh.SshConnect(host.host_ip(syslog_netconf_success.testbed,syslog_netconf_success.device))

        #config file from which config has to be sent as candidate config 
        config=config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        syslog_netconf_success.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        syslog_netconf_success.unconfig_file=config_file_dir+unconfig_file

        try :
            syslog_netconf_success.request = nexus.nxos_xmlin(d,syslog_netconf_success.device,syslog_netconf_success.config,'edit-config')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def syslog_test(self):
        self.obj = object()
        try :
            sessionid=syslog_netconf_success.nxos.nc_sshconnect(username=host.username(syslog_netconf_success.testbed,syslog_netconf_success.device),password=host.password(syslog_netconf_success.testbed,syslog_netconf_success.device))
            logging.info ('session-id is %s' %(sessionid))
            response =syslog_netconf_success.nxos._send(syslog_netconf_success.request)
            logging.info ('response is %s' % (response))
            time.sleep(10)
            send_line = 'sh logging logfile | grep RPC_OK | grep '+str(sessionid)
            output = nexus.nxos_exec(d,send_line)
            match=re.search('status:([a-zA-Z]+)',output)
            if match.group(1)=="SUCCESS" :
                logging.info('SUCCESS has been logged by syslog for the request sent')
            else :
                logging.error('Wrong syslog logged for the request sent')
                int_value=Failed.code
                assert int_value == 1
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            int_value=Passed.code
            assert int_value == 1
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        finally :
            close_message = syslog_netconf_success.nxos.closesession() 
            nexus.nxos_unconfig(d,syslog_netconf_success.unconfig_file)
            int_value=Passed.code
            assert int_value == 1 

class syslog_netconf_timeout(aetest.Testcase):

    logging.info ('checks if syslog after netconf session timed out')
    @aetest.setup
    def setup(self,testbed,device):
        self.obj = object()
        syslog_netconf_timeout.testbed = testbed
        syslog_netconf_timeout.device = device
        syslog_netconf_timeout.nxos = ncssh.SshConnect(host.host_ip(syslog_netconf_timeout.testbed,syslog_netconf_timeout.device))
        try :
            nexus.nxos_config(d,'xml server timeout 1',0)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def syslog_test(self):
        self.obj = object()
        try :
            sessionid=syslog_netconf_timeout.nxos.nc_sshconnect(username=host.username(syslog_netconf_timeout.testbed,syslog_netconf_timeout.device),password=host.password(syslog_netconf_timeout.testbed,syslog_netconf_timeout.device))
            logging.info ('session-id is %s' %(sessionid))
            time.sleep(60)
            send_line =  'show xml server status | grep ' + sessionid 
            output=nexus.nxos_exec(d,send_line)
            while sessionid in output:
                output=nexus.nxos_exec(d,send_line)
            else :
            	logging.info ('Netconf Session has timed out session id :' + sessionid)
            time.sleep(10)
            send_line = 'show logging logfile | grep timedout | grep '+sessionid
            output = nexus.nxos_exec(d,send_line)
            if sessionid in output :
                logging.info ('syslog logged for netconf session timedout')
                int_value = Passed.code
                assert int_value == 1
            else :
                logging.error('syslog not logged for netconf session timedout')
                int_value = Failed.code
                assert int_value == 1
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            nexus.nxos_config(d,'xml server timeout 1200',0)
            int_value=Passed.code
            assert int_value == 1
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1

class error_op_continue_on_error(aetest.Testcase):

    logging.info ('This testcase tests error option with error option as continue-on-error')

    @aetest.setup
    def setup(self,testbed,device,error_file,config_file_dir,unconfig_file):
        self.obj = object()
        error_op_continue_on_error.testbed = testbed
        error_op_continue_on_error.device = device
        error_op_continue_on_error.nxos = ncssh.SshConnect(host.host_ip(error_op_continue_on_error.testbed,error_op_continue_on_error.device))
        
        #config file from which config has to be sent
        config=error_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        error_op_continue_on_error.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        error_op_continue_on_error.unconfig_file=config_file_dir+unconfig_file
        
        try :

            error_op_continue_on_error.message = nexus.nxos_xmlin(d,error_op_continue_on_error.device,error_op_continue_on_error.config,'edit-config')
            request = command.error_option(error_op_continue_on_error.message,'continue-on-error')
            err_dict = {'6':'pending'}
            error_op_continue_on_error.request = command.build_error(request,**err_dict)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def error_test(self):
        self.obj = object()
        try :
            error_op_continue_on_error.nxos.nc_sshconnect(username=host.username(error_op_continue_on_error.testbed,error_op_continue_on_error.device),password=host.password(error_op_continue_on_error.testbed,error_op_continue_on_error.device))
            response =error_op_continue_on_error.nxos._send(error_op_continue_on_error.request,0)
            logging.info ('response is %s' % (response))
            args = ['6']
            nexus.verify_error(d,error_op_continue_on_error.config,'continue',*args)
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string,0)
            if error_list[1]=='invalid-value' :
                logging.info ('invalid value sent')
                logging.info ('error is %s' %error_list[3])
                int_value=Passed.code   
                assert int_value == 1 
            else :
                logging.debug ('Incorrect error returned')
                int_value=Failed.code
                assert int_value == 1

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = error_op_continue_on_error.nxos.closesession() 
        nexus.nxos_unconfig(d,error_op_continue_on_error.unconfig_file)
        int_value=Passed.code
        assert int_value == 1

class error_op_stop_on_error(aetest.Testcase):

    logging.info ('This testcase tests error option with error option as stop-on-error')
    @aetest.setup
    def setup(self,testbed,device,error_file,config_file_dir,unconfig_file):
        self.obj = object()
        error_op_stop_on_error.testbed = testbed
        error_op_stop_on_error.device = device
        error_op_stop_on_error.nxos = ncssh.SshConnect(host.host_ip(error_op_stop_on_error.testbed,error_op_stop_on_error.device))

        #config file from which config has to be sent 
        config=error_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        error_op_stop_on_error.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        error_op_stop_on_error.unconfig_file=config_file_dir+unconfig_file
        
        try :
            error_op_stop_on_error.message = nexus.nxos_xmlin(d,error_op_stop_on_error.device,error_op_stop_on_error.config,'edit-config')
            request = command.error_option(error_op_stop_on_error.message,'stop-on-error')
            err_dict = {'4':'0'}
            error_op_stop_on_error.request = command.build_error(request,**err_dict)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def error_test(self):
        self.obj = object()
        try :
            error_op_stop_on_error.nxos.nc_sshconnect(username=host.username(error_op_stop_on_error.testbed,error_op_stop_on_error.device),password=host.password(error_op_stop_on_error.testbed,error_op_stop_on_error.device))
            response =error_op_stop_on_error.nxos._send(error_op_stop_on_error.request,0)
            logging.info ('response is %s' % (response))
            args = ['4']
            nexus.verify_error(d,error_op_stop_on_error.config,'stop',*args)
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string,0)
            if error_list[1]=='invalid-value' :
                logging.info ('invalid value sent')
                logging.info ('error is %s' %error_list[3])
                int_value=Passed.code   
                assert int_value == 1 
            else :
                logging.debug ('Incorrect error returned')
                int_value=Failed.code
                assert int_value == 1

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = error_op_stop_on_error.nxos.closesession() 
        nexus.nxos_unconfig(d,error_op_stop_on_error.unconfig_file)
        int_value=Passed.code
        assert int_value == 1 

class error_op_rollback_on_error(aetest.Testcase):

    logging.info ('This testcase tests error option with error option as rollback-on-error')    
    @aetest.setup
    def setup(self,testbed,device,error_file,config_file_dir,unconfig_file):
        self.obj = object()
        error_op_rollback_on_error.testbed = testbed
        error_op_rollback_on_error.device = device
        error_op_rollback_on_error.nxos = ncssh.SshConnect(host.host_ip(error_op_rollback_on_error.testbed,error_op_rollback_on_error.device))
        
        #config file from which config has to be sent 
        config=error_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        error_op_rollback_on_error.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        error_op_rollback_on_error.unconfig_file=config_file_dir+unconfig_file
        
        try :
            error_op_rollback_on_error.message = nexus.nxos_xmlin(d,error_op_rollback_on_error.device,error_op_rollback_on_error.config,'edit-config')
            request = command.error_option(error_op_rollback_on_error.message,'rollback-on-error')
            err_dict = {'6':'pending'}
            error_op_rollback_on_error.request = command.build_error(request,**err_dict)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def error_test(self):
        self.obj = object()
        try :
            error_op_rollback_on_error.nxos.nc_sshconnect(username=host.username(error_op_rollback_on_error.testbed,error_op_rollback_on_error.device),password=host.password(error_op_rollback_on_error.testbed,error_op_rollback_on_error.device),command_timeout=200)
            response =error_op_rollback_on_error.nxos._send(error_op_rollback_on_error.request,0)
            logging.info ('response is %s' % (response))
            args = ['6']
            nexus.verify_error(d,error_op_rollback_on_error.config,'rollback',*args)
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.NotConnectedError :
            logging.ERROR ('SSH connection lost to the device')
            int_value=Failed.code
            assert int_value == 1        
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string,0)
            if error_list[1]=='invalid-value' :
                logging.info ('invalid value sent')
                logging.info ('error is %s' %error_list[3])
                int_value=Passed.code   
                assert int_value == 1 
            else :
                logging.debug ('Incorrect error returned')
                int_value=Failed.code
                assert int_value == 1

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = error_op_rollback_on_error.nxos.closesession() 
        nexus.nxos_unconfig(d,error_op_rollback_on_error.unconfig_file)
        int_value=Passed.code
        assert int_value == 1

class error_op_random_string(aetest.Testcase):

    logging.info ('This testcase tests error option with error option as random string')
    
    @aetest.setup
    def setup(self,testbed,device,error_file,config_file_dir,unconfig_file):
        self.obj = object()
        error_op_random_string.testbed = testbed
        error_op_random_string.device = device
        error_op_random_string.nxos = ncssh.SshConnect(host.host_ip(error_op_random_string.testbed,error_op_random_string.device))


        #config file from which config has to be sent 
        config=error_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        error_op_random_string.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        error_op_random_string.unconfig_file=config_file_dir+unconfig_file
        
        try :
            error_op_random_string.message = nexus.nxos_xmlin(d,error_op_random_string.device,error_op_random_string.config,'edit-config')
            request = command.error_option(error_op_random_string.message,'random')
            err_dict = {'6':'pending'}
            error_op_random_string.request = command.build_error(request,**err_dict)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def error_test(self):
        self.obj = object()
        try :
            error_op_random_string.nxos.nc_sshconnect(username=host.username(error_op_random_string.testbed,error_op_random_string.device),password=host.password(error_op_random_string.testbed,error_op_random_string.device))
            response =error_op_random_string.nxos._send(error_op_random_string.request,0)
            logging.info ('response is %s' % (response))
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string,0)
            if error_list[1]=='invalid-value' :
                logging.info ('invalid value sent')
                int_value=Passed.code   
                assert int_value == 1 
            else :
                logging.debug ('Incorrect error returned')
                int_value=Failed.code
                assert int_value == 1

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = error_op_random_string.nxos.closesession()
        nexus.nxos_unconfig(d,error_op_random_string.unconfig_file)        
        int_value=Passed.code
        assert int_value == 1 

        
class error_op_continue_on_error_without_error(aetest.Testcase):

    logging.info ('This testcase tests error option with error option as continue-on-error without error in request')

    @aetest.setup
    def setup(self,testbed,device,config_file,config_file_dir,unconfig_file):
        self.obj = object()
        error_op_continue_on_error_without_error.testbed = testbed
        error_op_continue_on_error_without_error.device = device
        error_op_continue_on_error_without_error.nxos = ncssh.SshConnect(host.host_ip(error_op_continue_on_error_without_error.testbed,error_op_continue_on_error_without_error.device))

        #config file from which config has to be sent 
        config=config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        error_op_continue_on_error_without_error.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        error_op_continue_on_error_without_error.unconfig_file=config_file_dir+unconfig_file
        
        try :
            error_op_continue_on_error_without_error.message = nexus.nxos_xmlin(d,error_op_continue_on_error_without_error.device,error_op_continue_on_error_without_error.config,'edit-config')
            error_op_continue_on_error_without_error.request = command.error_option(error_op_continue_on_error_without_error.message,'continue-on-error')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def error_test(self):
        self.obj = object()
        try :
            error_op_continue_on_error_without_error.nxos.nc_sshconnect(username=host.username(error_op_continue_on_error_without_error.testbed,error_op_continue_on_error_without_error.device),password=host.password(error_op_continue_on_error_without_error.testbed,error_op_continue_on_error_without_error.device))
            response =error_op_continue_on_error_without_error.nxos._send(error_op_continue_on_error_without_error.request)
            logging.info ('response is %s' % (response))
            nexus.verify_default_op(d,error_op_continue_on_error_without_error.config,'merge')
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = error_op_continue_on_error_without_error.nxos.closesession() 
        nexus.nxos_unconfig(d,error_op_continue_on_error_without_error.unconfig_file)
        int_value=Passed.code
        assert int_value == 1 

class error_op_stop_on_error_without_error(aetest.Testcase):

    logging.info ('This testcase tests error option with error option as stop-on-error without error in request')
    
    @aetest.setup
    def setup(self,testbed,device,config_file,config_file_dir,unconfig_file):
        self.obj = object()
        error_op_stop_on_error_without_error.testbed = testbed
        error_op_stop_on_error_without_error.device = device
        error_op_stop_on_error_without_error.nxos = ncssh.SshConnect(host.host_ip(error_op_stop_on_error_without_error.testbed,error_op_stop_on_error_without_error.device))
        #config file from which config has to be sent 
        config=config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        error_op_stop_on_error_without_error.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        error_op_stop_on_error_without_error.unconfig_file=config_file_dir+unconfig_file
        
        try :
            error_op_stop_on_error_without_error.message = nexus.nxos_xmlin(d,error_op_stop_on_error_without_error.device,error_op_stop_on_error_without_error.config,'edit-config')
            error_op_stop_on_error_without_error.request = command.error_option(error_op_stop_on_error_without_error.message,'stop-on-error')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def error_test(self):
        self.obj = object()
        try :
            error_op_stop_on_error_without_error.nxos.nc_sshconnect(username=host.username(error_op_stop_on_error_without_error.testbed,error_op_stop_on_error_without_error.device),password=host.password(error_op_stop_on_error_without_error.testbed,error_op_stop_on_error_without_error.device))
            response =error_op_stop_on_error_without_error.nxos._send(error_op_stop_on_error_without_error.request)
            logging.info ('response is %s' % (response))
            nexus.verify_default_op(d,error_op_stop_on_error_without_error.config,'merge')
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = error_op_stop_on_error_without_error.nxos.closesession() 
        nexus.nxos_unconfig(d,error_op_stop_on_error_without_error.unconfig_file)
        int_value=Passed.code
        assert int_value == 1 

       
class error_op_rollback_on_error_without_error(aetest.Testcase):

    logging.info ('This testcase tests error option with error option as rollback-on-error without error in request')

    @aetest.setup
    def setup(self,testbed,device,config_file,config_file_dir,unconfig_file):
        self.obj = object()
        error_op_rollback_on_error_without_error.testbed = testbed
        error_op_rollback_on_error_without_error.device = device
        error_op_rollback_on_error_without_error.nxos = ncssh.SshConnect(host.host_ip(error_op_rollback_on_error_without_error.testbed,error_op_rollback_on_error_without_error.device))

        #config file from which config has to be sent 
        config=config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        error_op_rollback_on_error_without_error.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        error_op_rollback_on_error_without_error.unconfig_file=config_file_dir+unconfig_file
        
        try :
            error_op_rollback_on_error_without_error.message = nexus.nxos_xmlin(d,error_op_rollback_on_error_without_error.device,error_op_rollback_on_error_without_error.config,'edit-config')
            error_op_rollback_on_error_without_error.request = command.error_option(error_op_rollback_on_error_without_error.message,'rollback-on-error')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def error_test(self):
        self.obj = object()
        try :
            error_op_rollback_on_error_without_error.nxos.nc_sshconnect(username=host.username(error_op_rollback_on_error_without_error.testbed,error_op_rollback_on_error_without_error.device),password=host.password(error_op_rollback_on_error_without_error.testbed,error_op_rollback_on_error_without_error.device))
            response =error_op_rollback_on_error_without_error.nxos._send(error_op_rollback_on_error_without_error.request)
            logging.info ('response is %s' % (response))
            nexus.verify_default_op(d,error_op_rollback_on_error_without_error.config,'merge')
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = error_op_rollback_on_error_without_error.nxos.closesession() 
        nexus.nxos_unconfig(d,error_op_rollback_on_error_without_error.unconfig_file)
        int_value=Passed.code
        assert int_value == 1 

class test_op_set_edit_config(aetest.Testcase):

    logging.info  ("This testcase tests the test option as set for the edit config sent")
    
    @aetest.setup
    def setup(self,testbed,device,error_file,config_file_dir,unconfig_file):
        self.obj = object()
        test_op_set_edit_config.testbed = testbed
        test_op_set_edit_config.device = device
        test_op_set_edit_config.nxos = ncssh.SshConnect(host.host_ip(test_op_set_edit_config.testbed,test_op_set_edit_config.device))
        #config file from which config has to be sent 
        config=error_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        test_op_set_edit_config.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        test_op_set_edit_config.unconfig_file=config_file_dir+unconfig_file
        try :
            test_op_set_edit_config.message = nexus.nxos_xmlin(d,test_op_set_edit_config.device,test_op_set_edit_config.config,'edit-config')
            request = command.test_option(test_op_set_edit_config.message,'set')
            err_dict = {'4':'bandwith 0'}
            test_op_set_edit_config.request = command.build_error(request,**err_dict)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def test(self):
        self.obj = object()
        try :
            test_op_set_edit_config.nxos.nc_sshconnect(username=host.username(test_op_set_edit_config.testbed,test_op_set_edit_config.device),password=host.password(test_op_set_edit_config.testbed,test_op_set_edit_config.device))
            response =test_op_set_edit_config.nxos._send(test_op_set_edit_config.request,0)
            logging.info ('response is %s' % (response))
            args = ['4']
            nexus.verify_error(d,test_op_set_edit_config.config,'stop',*args)
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string,0)
            if error_list[1]=='invalid-value' :
                logging.info ('invalid value sent')
                logging.info ('error is %s' %error_list[3])
                int_value=Passed.code   
                assert int_value == 1 
            else :
                logging.debug ('Incorrect error returned')
                int_value=Failed.code
                assert int_value == 1 
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = test_op_set_edit_config.nxos.closesession()
        nexus.nxos_unconfig(d,test_op_set_edit_config.unconfig_file)
        int_value=Passed.code
        assert int_value == 1 

        
class test_op_test_then_set_edit_config(aetest.Testcase):

    logging.info  ("This testcase tests the test option as test-then-set for the edit config sent")
    
    @aetest.setup
    def setup(self,testbed,device,error_file,config_file_dir,unconfig_file):
        self.obj = object()
        test_op_test_then_set_edit_config.testbed = testbed
        test_op_test_then_set_edit_config.device = device
        test_op_test_then_set_edit_config.nxos = ncssh.SshConnect(host.host_ip(test_op_test_then_set_edit_config.testbed,test_op_test_then_set_edit_config.device))
        #config file from which config has to be sent 
        config=error_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        test_op_test_then_set_edit_config.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        test_op_test_then_set_edit_config.unconfig_file=config_file_dir+unconfig_file
        try :
            test_op_test_then_set_edit_config.message = nexus.nxos_xmlin(d,test_op_test_then_set_edit_config.device,test_op_test_then_set_edit_config.config,'edit-config')
            request = command.test_option(test_op_test_then_set_edit_config.message,'test-then-set')
            err_dict = {'4':'bandwith 0'}
            test_op_test_then_set_edit_config.request = command.build_error(request,**err_dict)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def validate_test(self):
        self.obj = object()
        try :
            test_op_test_then_set_edit_config.nxos.nc_sshconnect(username=host.username(test_op_test_then_set_edit_config.testbed,test_op_test_then_set_edit_config.device),password=host.password(test_op_test_then_set_edit_config.testbed,test_op_test_then_set_edit_config.device))
            response =test_op_test_then_set_edit_config.nxos._send(test_op_test_then_set_edit_config.request,0)
            logging.info ('response is %s' % (response))
            args = ['4']
            nexus.verify_error(d,test_op_test_then_set_edit_config.config,'rollback',*args)
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string,0)
            if error_list[1]=='invalid-value' :
                logging.info ('invalid value sent')
                logging.info ('error is %s' %error_list[3])
                int_value=Passed.code   
                assert int_value == 1 
            else :
                logging.debug ('Incorrect error returned')
                int_value=Failed.code
                assert int_value == 1
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = test_op_test_then_set_edit_config.nxos.closesession()
        nexus.nxos_unconfig(d,test_op_test_then_set_edit_config.unconfig_file)
        int_value=Passed.code
        assert int_value == 1 

class test_op_random_string_for_edit_config(aetest.Testcase):

    logging.info  ("This testcase tests the test option as any random string for the edit config sent")
    
    @aetest.setup
    def setup(self,testbed,device,error_file,config_file_dir,unconfig_file):
        self.obj = object()
        test_op_random_string_for_edit_config.testbed = testbed
        test_op_random_string_for_edit_config.device = device
        test_op_random_string_for_edit_config.nxos = ncssh.SshConnect(host.host_ip(test_op_random_string_for_edit_config.testbed,test_op_random_string_for_edit_config.device))

        #config file from which config has to be sent 
        config=error_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        test_op_random_string_for_edit_config.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        test_op_random_string_for_edit_config.unconfig_file=config_file_dir+unconfig_file
        try :
            test_op_random_string_for_edit_config.message = nexus.nxos_xmlin(d,test_op_random_string_for_edit_config.device,test_op_random_string_for_edit_config.config,'edit-config')
            request = command.test_option(test_op_random_string_for_edit_config.message,'random')
            err_dict = {'4':'bandwith 0'}
            test_op_random_string_for_edit_config.request = command.build_error(request,**err_dict)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def test(self):
        self.obj = object()
        try :
            test_op_random_string_for_edit_config.nxos.nc_sshconnect(username=host.username(test_op_random_string_for_edit_config.testbed,test_op_random_string_for_edit_config.device),password=host.password(test_op_random_string_for_edit_config.testbed,test_op_random_string_for_edit_config.device))
            response =test_op_random_string_for_edit_config.nxos._send(test_op_random_string_for_edit_config.request,0)
            logging.info ('response is %s' % (response))
            args = ['4']
            nexus.verify_error(d,test_op_random_string_for_edit_config.config,'rollback',*args)
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string,0)
            if error_list[1]=='invalid-value' :
                logging.info ('invalid value sent')
                logging.info ('error is %s' %error_list[3])
                int_value=Passed.code   
                assert int_value == 1 
            else :
                logging.debug ('Incorrect error returned')
                int_value=Failed.code
                assert int_value == 1
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = test_op_random_string_for_edit_config.nxos.closesession()
        int_value=Passed.code
        assert int_value == 1

class test_op_set_edit_config_without_error(aetest.Testcase):

    logging.info  ("This testcase tests the test option as set for the edit config sent without error")
    
    @aetest.setup
    def setup(self,testbed,device,config_file,config_file_dir,unconfig_file):
        self.obj = object()
        test_op_set_edit_config_without_error.testbed = testbed
        test_op_set_edit_config_without_error.device = device
        test_op_set_edit_config_without_error.nxos = ncssh.SshConnect(host.host_ip(test_op_set_edit_config_without_error.testbed,test_op_set_edit_config_without_error.device))

        #config file from which config has to be sent 
        config=config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        test_op_set_edit_config_without_error.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        test_op_set_edit_config_without_error.unconfig_file=config_file_dir+unconfig_file
        try :
            test_op_set_edit_config_without_error.message = nexus.nxos_xmlin(d,test_op_set_edit_config_without_error.device,test_op_set_edit_config_without_error.config,'edit-config')
            test_op_set_edit_config_without_error.request = command.test_option(test_op_set_edit_config_without_error.message,'set')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def validate_test(self):
        self.obj = object()
        try :
            test_op_set_edit_config_without_error.nxos.nc_sshconnect(username=host.username(test_op_set_edit_config_without_error.testbed,test_op_set_edit_config_without_error.device),password=host.password(test_op_set_edit_config_without_error.testbed,test_op_set_edit_config_without_error.device))
            response =test_op_set_edit_config_without_error.nxos._send(test_op_set_edit_config_without_error.request)
            logging.info ('response is %s' % (response))
            nexus.verify_default_op(d,test_op_set_edit_config_without_error.config,'merge')
            int_value=Passed.code   
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = test_op_set_edit_config_without_error.nxos.closesession()
        nexus.nxos_unconfig(d,test_op_set_edit_config_without_error.unconfig_file)
        int_value=Passed.code
        assert int_value == 1 
        
class test_op_test_then_set_edit_config_without_error(aetest.Testcase):

    logging.info  ("This testcase tests the test option as test-then-set for the edit config sent without error")
        
    @aetest.setup
    def setup(self,testbed,device,config_file,config_file_dir,unconfig_file):
        self.obj = object()
        test_op_test_then_set_edit_config_without_error.testbed = testbed
        test_op_test_then_set_edit_config_without_error.device = device
        test_op_test_then_set_edit_config_without_error.nxos = ncssh.SshConnect(host.host_ip(test_op_test_then_set_edit_config_without_error.testbed,test_op_test_then_set_edit_config_without_error.device))
        #config file from which config has to be sent 
        config=config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        test_op_test_then_set_edit_config_without_error.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        test_op_test_then_set_edit_config_without_error.unconfig_file=config_file_dir+unconfig_file
        try :
            test_op_test_then_set_edit_config_without_error.message = nexus.nxos_xmlin(d,test_op_test_then_set_edit_config_without_error.device,test_op_test_then_set_edit_config_without_error.config,'edit-config')
            test_op_test_then_set_edit_config_without_error.request = command.test_option(test_op_test_then_set_edit_config_without_error.message,'test-then-set')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def validate_test(self):
        self.obj = object()
        try :
            test_op_test_then_set_edit_config_without_error.nxos.nc_sshconnect(username=host.username(test_op_test_then_set_edit_config_without_error.testbed,test_op_test_then_set_edit_config_without_error.device),password=host.password(test_op_test_then_set_edit_config_without_error.testbed,test_op_test_then_set_edit_config_without_error.device))
            response =test_op_test_then_set_edit_config_without_error.nxos._send(test_op_test_then_set_edit_config_without_error.request)
            logging.info ('response is %s' % (response))
            nexus.verify_default_op(d,test_op_test_then_set_edit_config_without_error.config,'merge')
            int_value=Passed.code   
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = test_op_test_then_set_edit_config_without_error.nxos.closesession()
        nexus.nxos_unconfig(d,test_op_test_then_set_edit_config_without_error.unconfig_file)
        int_value=Passed.code
        assert int_value == 1

class validate_running_config_copied_to_file(aetest.Testcase):

    logging.info  ("This testcase tests the validate option against the running config copied into a file")
    
    @aetest.setup
    def setup(self,testbed,device,config_file,config_file_dir):
        self.obj = object()
        validate_running_config_copied_to_file.testbed = testbed
        validate_running_config_copied_to_file.device = device
        validate_running_config_copied_to_file.nxos = ncssh.SshConnect(host.host_ip(validate_running_config_copied_to_file.testbed,validate_running_config_copied_to_file.device))

        #config file from which config has to be sent 
        config=config_file

        config_file = config_file_dir+config
        try :
            nexus.copy_file(validate_running_config_copied_to_file.testbed,d,config_file)
            line = 'file://'+config
            validate_running_config_copied_to_file.message = command.validate_req(line)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def validate_test(self):
        self.obj = object()
        try :
            validate_running_config_copied_to_file.nxos.nc_sshconnect(username=host.username(validate_running_config_copied_to_file.testbed,validate_running_config_copied_to_file.device),password=host.password(validate_running_config_copied_to_file.testbed,validate_running_config_copied_to_file.device))
            response =validate_running_config_copied_to_file.nxos._send(validate_running_config_copied_to_file.message)
            logging.info ('response is %s' % (response))
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = validate_running_config_copied_to_file.nxos.closesession() 
        int_value=Passed.code
        assert int_value == 1 
        
class validate_file_not_present_in_bootflash(aetest.Testcase):

    logging.info  ("This testcase tests the validate option against a file which is not present in bootflash")
    
    @aetest.setup
    def setup(self,testbed,device):
        self.obj = object()
        validate_file_not_present_in_bootflash.testbed = testbed
        validate_file_not_present_in_bootflash.device = device
        validate_file_not_present_in_bootflash.nxos = ncssh.SshConnect(host.host_ip(validate_file_not_present_in_bootflash.testbed,validate_file_not_present_in_bootflash.device))
        try :
            validate_file_not_present_in_bootflash.message = command.validate_req('file://bdjkd.cfg')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def validate_test(self):
        self.obj = object()
        try :
            validate_file_not_present_in_bootflash.nxos.nc_sshconnect(username=host.username(validate_file_not_present_in_bootflash.testbed,validate_file_not_present_in_bootflash.device),password=host.password(validate_file_not_present_in_bootflash.testbed,validate_file_not_present_in_bootflash.device))
            # sending Rpcparse as false to ignore NetConfRPCError in order to parse the error
            response =validate_file_not_present_in_bootflash.nxos._send(validate_file_not_present_in_bootflash.message,0)
            logging.info ('response is %s' % (response))
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string)
            if error_list[3] == "No such file or directory" :
                logging.info ('correct error returned')
                int_value=Passed.code
                assert int_value == 1
            else :
                logging.debug("Incorrect error returned")
                int_value=Failed.code
                assert int_value == 1

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = validate_file_not_present_in_bootflash.nxos.closesession() 
        int_value=Passed.code
        assert int_value == 1
        
class validate_unsupported_type_url(aetest.Testcase):

    logging.info  ("This testcase tests the validate option against an unsupported type of url")
    
    @aetest.setup
    def setup(self,testbed,device):
        self.obj = object()
        validate_unsupported_type_url.testbed = testbed
        validate_unsupported_type_url.device = device
        validate_unsupported_type_url.nxos = ncssh.SshConnect(host.host_ip(validate_unsupported_type_url.testbed,validate_unsupported_type_url.device))
        try :
            validate_unsupported_type_url.message = command.validate_req('http://validate-runn-config')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def validate_test(self):
        self.obj = object()
        try :
            validate_unsupported_type_url.nxos.nc_sshconnect(username=host.username(validate_unsupported_type_url.testbed,validate_unsupported_type_url.device),password=host.password(validate_unsupported_type_url.testbed,validate_unsupported_type_url.device))
            #sending Rpcparse as false to ignore NetConfRPCError in order to parse the error
            response =validate_unsupported_type_url.nxos._send(validate_unsupported_type_url.message,False)
            logging.info ('response is %s' % (response))
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string)
            if error_list[1] == "operation-not-supported" and error_list[3] == "Currently not supported" : 
                logging.info ('correct error returned')
                int_value=Passed.code
                assert int_value == 1
            else :
                logging.debug("Incorrect error returned")
                int_value=Failed.code
                assert int_value == 1

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = validate_unsupported_type_url.nxos.closesession() 
        int_value=Passed.code
        assert int_value == 1                 
            
class validate_empty_filename(aetest.Testcase):

    logging.info  ("This testcase tests the validate option against an empty file name")
    
    @aetest.setup
    def setup(self,testbed,device):
        self.obj = object()
        validate_empty_filename.testbed = testbed
        validate_empty_filename.device = device
        validate_empty_filename.nxos = ncssh.SshConnect(host.host_ip(validate_empty_filename.testbed,validate_empty_filename.device))
        try :
            validate_empty_filename.message = command.validate_req("")
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def validate_test(self):
        self.obj = object()
        try :
            validate_empty_filename.nxos.nc_sshconnect(username=host.username(validate_empty_filename.testbed,validate_empty_filename.device),password=host.password(validate_empty_filename.testbed,validate_empty_filename.device))
            # sending Rpcparse as false to ignore NetConfRPCError in order to parse the error
            response =validate_empty_filename.nxos._send(validate_empty_filename.message,False)
            logging.info ('response is %s' % (response))
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string)
            if error_list[3] == "File name is empty" : 
                logging.info ('correct error returned')
                int_value=Passed.code
                assert int_value == 1
            else :
                logging.debug("Incorrect error returned")
                int_value=Failed.code
                assert int_value == 1

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = validate_empty_filename.nxos.closesession() 
        int_value=Passed.code
        assert int_value == 1 
                
class validate_filename_morethan_255_charecters(aetest.Testcase):

    logging.info  ("This testcase tests the validate option against file with name more than 255 charecters")
    
    @aetest.setup
    def setup(self,testbed,device):
        self.obj = object()
        validate_filename_morethan_255_charecters.testbed = testbed
        validate_filename_morethan_255_charecters.device = device
        validate_filename_morethan_255_charecters.nxos = ncssh.SshConnect(host.host_ip(validate_filename_morethan_255_charecters.testbed,validate_filename_morethan_255_charecters.device))
        try :
            #creating a random file name with more than 255 allowed charecters
            file=''.join(random.choice(string.ascii_lowercase) for _ in xrange(256))
            filename = 'file://'+file
            validate_filename_morethan_255_charecters.message = command.validate_req(filename)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def validate_test(self):
        self.obj = object()
        try :
            validate_filename_morethan_255_charecters.nxos.nc_sshconnect(username=host.username(validate_filename_morethan_255_charecters.testbed,validate_filename_morethan_255_charecters.device),password=host.password(validate_filename_morethan_255_charecters.testbed,validate_filename_morethan_255_charecters.device))
            #sending Rpcparse as false to ignore NetConfRPCError in order to parse the error
            response =validate_filename_morethan_255_charecters.nxos._send(validate_filename_morethan_255_charecters.message,False)
            logging.info ('response is %s' % (response))
        finally :
            
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string)
            if error_list[1] == "too-big" and error_list[3] == "File name length is too long(max length 255)" : 
                logging.info ('correct error returned')
                int_value=Passed.code
                assert int_value == 1
            else :
                logging.debug("Incorrect error returned")
                int_value=Failed.code
                assert int_value == 1

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = validate_filename_morethan_255_charecters.nxos.closesession() 
        int_value=Passed.code
        assert int_value == 1 

class validate_edit_config(aetest.Testcase):

    logging.info  ("This testcase tests the validate with edit-config request")
    
    @aetest.setup
    def setup(self,testbed,device,config_file,config_file_dir):
        self.obj = object()
        validate_edit_config.testbed = testbed
        validate_edit_config.device = device
        validate_edit_config.nxos = ncssh.SshConnect(host.host_ip(validate_edit_config.testbed,validate_edit_config.device))

        #config file from which config has to be sent 
        config=config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        config = command.cmd_req('edit-config',config_file)

        try :
            message=nexus.nxos_xmlin(d,validate_edit_config.device,config,'edit-config')
            validate_edit_config.message = command.validate_edit(message)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def validate_test(self):
        self.obj = object()
        try :
            validate_edit_config.nxos.nc_sshconnect(username=host.username(validate_edit_config.testbed,validate_edit_config.device),password=host.password(validate_edit_config.testbed,validate_edit_config.device))
            response =validate_edit_config.nxos._send(validate_edit_config.message)
            logging.info ('response is %s' % (response))
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = validate_edit_config.nxos.closesession() 
        int_value=Passed.code
        assert int_value == 1 
        
class validate_errored_edit_config(aetest.Testcase):

    logging.info  ("This testcase tests the validate with errored edit-config request")
    
    @aetest.setup
    def setup(self,testbed,device,error_file,config_file_dir):
        self.obj = object()
        validate_errored_edit_config.testbed = testbed
        validate_errored_edit_config.device = device
        validate_errored_edit_config.nxos = ncssh.SshConnect(host.host_ip(validate_errored_edit_config.testbed,validate_errored_edit_config.device))
        
        #config file from which config has to be sent 
        config=error_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        config = command.cmd_req('edit-config',config_file)

        try :
            message=nexus.nxos_xmlin(d,validate_errored_edit_config.device,config,'edit-config')
            err_dict = {'6':'pending'}
            error_message =  command.build_error(message,**err_dict)
            validate_errored_edit_config.message = command.validate_edit(error_message)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def validate_test(self):
        self.obj = object()
        try :
            validate_errored_edit_config.nxos.nc_sshconnect(username=host.username(validate_errored_edit_config.testbed,validate_errored_edit_config.device),password=host.password(validate_errored_edit_config.testbed,validate_errored_edit_config.device))
            response =validate_errored_edit_config.nxos._send(validate_errored_edit_config.message,0)
            logging.info ('response is %s' % (response))
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string,0)
            if error_list[1]=='invalid-value' :
                logging.info ('invalid value sent')
                logging.info ('error is %s' %error_list[3])
                int_value=Passed.code   
                assert int_value == 1 
            else :
                logging.debug ('Incorrect error returned')
                int_value=Failed.code
                assert int_value == 1

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = validate_errored_edit_config.nxos.closesession() 
        int_value=Passed.code
        assert int_value == 1

class copy_running_config_to_file(aetest.Testcase):

    logging.info  ("This testcase tests the copy config by copying running config into a file")
    
    @aetest.setup
    def setup(self,testbed,device):
        self.obj = object()
        copy_running_config_to_file.testbed = testbed
        copy_running_config_to_file.device = device
        copy_running_config_to_file.nxos = ncssh.SshConnect(host.host_ip(copy_running_config_to_file.testbed,copy_running_config_to_file.device))
        try :
            copy_running_config_to_file.message = command.copy_config(1,0,'running','abc.cfg')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def copy_conf_test(self):
        self.obj = object()
        try :
            copy_running_config_to_file.nxos.nc_sshconnect(username=host.username(copy_running_config_to_file.testbed,copy_running_config_to_file.device),password=host.password(copy_running_config_to_file.testbed,copy_running_config_to_file.device),command_timeout=500)
            response =copy_running_config_to_file.nxos._send(copy_running_config_to_file.message)
            logging.info ('response is %s' % (response))
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = copy_running_config_to_file.nxos.closesession() 
        int_value=Passed.code
        assert int_value == 1 

class copy_file_to_running_config(aetest.Testcase):

    logging.info  ("This testcase tests the copy config by copying config from file to running config")
    
    @aetest.setup
    def setup(self,testbed,device):
        self.obj = object()
        copy_file_to_running_config.testbed = testbed
        copy_file_to_running_config.device = device
        copy_file_to_running_config.nxos = ncssh.SshConnect(host.host_ip(copy_file_to_running_config.testbed,copy_file_to_running_config.device))
        try :
            copy_file_to_running_config.message = command.copy_config(1,1,'abc.cfg','running')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def copy_conf_test(self):
        self.obj = object()
        try :
            copy_file_to_running_config.nxos.nc_sshconnect(username=host.username(copy_file_to_running_config.testbed,copy_file_to_running_config.device),password=host.password(copy_file_to_running_config.testbed,copy_file_to_running_config.device),command_timeout=500)
            response =copy_file_to_running_config.nxos._send(copy_file_to_running_config.message)
            logging.info ('response is %s' % (response))
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = copy_file_to_running_config.nxos.closesession() 
        int_value=Passed.code
        assert int_value == 1 

class copy_running_config_to_file_with_target_first(aetest.Testcase):

    logging.info  ("This testcase tests the copy config by copying running config into a file with target given first")
    
    @aetest.setup
    def setup(self,testbed,device):
        self.obj = object()
        copy_running_config_to_file_with_target_first.testbed = testbed
        copy_running_config_to_file_with_target_first.device = device
        copy_running_config_to_file_with_target_first.nxos = ncssh.SshConnect(host.host_ip(copy_running_config_to_file_with_target_first.testbed,copy_running_config_to_file_with_target_first.device))
        try :
            copy_running_config_to_file_with_target_first.message = command.copy_config(0,0,'running','test.cfg')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def copy_conf_test(self):
        self.obj = object()
        try :
            copy_running_config_to_file_with_target_first.nxos.nc_sshconnect(username=host.username(copy_running_config_to_file_with_target_first.testbed,copy_running_config_to_file_with_target_first.device),password=host.password(copy_running_config_to_file_with_target_first.testbed,copy_running_config_to_file_with_target_first.device),command_timeout=500)
            response =copy_running_config_to_file_with_target_first.nxos._send(copy_running_config_to_file_with_target_first.message)
            logging.info ('response is %s' % (response))
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = copy_running_config_to_file_with_target_first.nxos.closesession() 
        int_value=Passed.code
        assert int_value == 1 

class copy_file_to_running_config_with_target_first(aetest.Testcase):

    logging.info  ("This testcase tests the copy config by copying config from file to running config with target given first")
    
    @aetest.setup
    def setup(self,testbed,device):
        self.obj = object()
        copy_file_to_running_config_with_target_first.testbed = testbed
        copy_file_to_running_config_with_target_first.device = device
        copy_file_to_running_config_with_target_first.nxos = ncssh.SshConnect(host.host_ip(copy_file_to_running_config_with_target_first.testbed,copy_file_to_running_config_with_target_first.device))
        try :
            copy_file_to_running_config_with_target_first.message = command.copy_config(0,1,'test.cfg','running')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def copy_conf_test(self):
        self.obj = object()
        try :
            copy_file_to_running_config_with_target_first.nxos.nc_sshconnect(username=host.username(copy_file_to_running_config_with_target_first.testbed,copy_file_to_running_config_with_target_first.device),password=host.password(copy_file_to_running_config_with_target_first.testbed,copy_file_to_running_config_with_target_first.device),command_timeout=500)
            response =copy_file_to_running_config_with_target_first.nxos._send(copy_file_to_running_config_with_target_first.message)
            logging.info ('response is %s' % (response))
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = copy_file_to_running_config_with_target_first.nxos.closesession() 
        int_value=Passed.code
        assert int_value == 1 
 
class copy_invalid_url_as_source(aetest.Testcase):

    logging.info  ("This testcase tests the copy config by giving invalid url as source")
    
    @aetest.setup
    def setup(self,testbed,device):
        self.obj = object()
        copy_invalid_url_as_source.testbed = testbed
        copy_invalid_url_as_source.device = device
        copy_invalid_url_as_source.nxos = ncssh.SshConnect(host.host_ip(copy_invalid_url_as_source.testbed,copy_invalid_url_as_source.device))
        try :
            copy_invalid_url_as_source.message = '''<rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
                                        <copy-config>
                                        <source>
                                            <url>http:xxx</url>
                                        </source>
                                        <target>
                                            <running/>
                                        </target>
                                        </copy-config>
                                        </rpc>'''
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def copy_config_test(self):
        self.obj = object()
        try :
            copy_invalid_url_as_source.nxos.nc_sshconnect(username=host.username(copy_invalid_url_as_source.testbed,copy_invalid_url_as_source.device),password=host.password(copy_invalid_url_as_source.testbed,copy_invalid_url_as_source.device))
            response =copy_invalid_url_as_source.nxos._send(copy_invalid_url_as_source.message,0)
            logging.info ('response is %s' % (response))

        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string,0)
            if error_list[1]=='operation-not-supported' and error_list[3]=='Currently not supported' :
                logging.info ('invalid value sent')
                logging.info ('error is %s' %error_list[3])
                int_value=Passed.code   
                assert int_value == 1 
            else :
                logging.debug ('Incorrect error returned')
                int_value=Failed.code
                assert int_value == 1

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = copy_invalid_url_as_source.nxos.closesession() 
        int_value=Passed.code
        assert int_value == 1 

class lock_running_as_target(aetest.Testcase):

    logging.info  ("This testcase tests the lock option with running as the target")
    
    @aetest.setup
    def setup(self,testbed,device):
        self.obj = object()
        lock_running_as_target.testbed = testbed
        lock_running_as_target.device = device
        lock_running_as_target.nxos = ncssh.SshConnect(host.host_ip(lock_running_as_target.testbed,lock_running_as_target.device))
        try :
            lock_running_as_target.message = command.lock_request('running')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def lock_test(self):
        self.obj = object()
        try :
            sessionid=lock_running_as_target.nxos.nc_sshconnect(username=host.username(lock_running_as_target.testbed,lock_running_as_target.device),password=host.password(lock_running_as_target.testbed,lock_running_as_target.device))
            logging.info ('session-id is %s' %(sessionid))
            response =lock_running_as_target.nxos._send(lock_running_as_target.message,1)
            logging.info ('response is %s' % (response))
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('lock request Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            unlock_message = command.unlock_request('running')
            respone = lock_running_as_target.nxos._send(unlock_message,1)
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('unlock request Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        finally :
            close_message = lock_running_as_target.nxos.closesession() 
            int_value=Passed.code
            assert int_value == 1  
      
class lock_startup_as_target(aetest.Testcase):

    logging.info  ("This testcase tests the lock option with startup as the target")
    
    @aetest.setup
    def setup(self,testbed,device):
        self.obj = object()
        lock_startup_as_target.testbed = testbed
        lock_startup_as_target.device = device
        lock_startup_as_target.nxos = ncssh.SshConnect(host.host_ip(lock_startup_as_target.testbed,lock_startup_as_target.device))
        try :
            lock_startup_as_target.message = command.lock_request('startup')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def lock_test(self):
        self.obj = object()
        try :
            sessionid=lock_startup_as_target.nxos.nc_sshconnect(username=host.username(lock_startup_as_target.testbed,lock_startup_as_target.device),password=host.password(lock_startup_as_target.testbed,lock_startup_as_target.device))
            logging.info ('session-id is %s' %(sessionid))
            response = lock_startup_as_target.nxos._send(lock_startup_as_target.message,0)
            logging.info ('response is %s' % (response))
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string)
            error_message = "Wrong config source,only running config and candidate is supported "
            if error_list[1] == "operation-not-supported" and error_list[3] == error_message and error_list[4]== "startup" :
                logging.info ('correct error returned')
                int_value=Passed.code
                assert int_value == 1
            else :
                logging.error("Incorrect error returned")
                int_value=Failed.code
                assert int_value == 1
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()

        close_message = lock_startup_as_target.nxos.closesession() 
        int_value=Passed.code
        assert int_value == 1 
            
class lock_hold_locks_already(aetest.Testcase):

    logging.info  ("This testcase tests the lock option with a session that holds locks already")
    
    @aetest.setup
    def setup(self,testbed,device):
        self.obj = object()
        lock_hold_locks_already.testbed = testbed
        lock_hold_locks_already.device = device
        lock_hold_locks_already.nxos = ncssh.SshConnect(host.host_ip(lock_hold_locks_already.testbed,lock_hold_locks_already.device))
        try :
            lock_hold_locks_already.message = command.lock_request('running')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def lock_test(self):
        self.obj = object()
        try :
            sessionid=lock_hold_locks_already.nxos.nc_sshconnect(username=host.username(lock_hold_locks_already.testbed,lock_hold_locks_already.device),password=host.password(lock_hold_locks_already.testbed,lock_hold_locks_already.device))
            logging.info ('session-id is %s' %(sessionid))
            response =lock_hold_locks_already.nxos._send(lock_hold_locks_already.message,1)
            logging.info ('response is %s' % (response))
            logging.info ('lock acquired from this session')
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('lock request Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        
        try :
            response =lock_hold_locks_already.nxos._send(lock_hold_locks_already.message,0)
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string)
            if error_list[1]=='lock-denied' and error_list[3]=='Lock Failed, lock is already held' and error_list[4] == sessionid :
                logging.info ('Lock is already acquired from the session with id %s' %(sessionid))
                int_value=Passed.code   
                assert int_value == 1 
            else :
                logging.error ('Incorrect error returned')
                int_value=Failed.code
                assert int_value == 1
    
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            unlock_message = command.unlock_request('running')
            respone = lock_hold_locks_already.nxos._send(unlock_message,1)
            int_value=Passed.code
            assert int_value == 1
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        finally :
            close_message = lock_hold_locks_already.nxos.closesession() 
            int_value=Passed.code
            assert int_value == 1   
            
class lock_hold_locks_already_send_lock_2nd_session(aetest.Testcase):

    logging.info  ("This testcase tests the lock option with a session that holds locks already and send lock request through second session")
    
    @aetest.setup
    def setup(self,testbed,device):
        self.obj = object()  
        lock_hold_locks_already_send_lock_2nd_session.testbed = testbed
        lock_hold_locks_already_send_lock_2nd_session.device = device
        lock_hold_locks_already_send_lock_2nd_session.nxos1 = ncssh.SshConnect(host.host_ip(lock_hold_locks_already_send_lock_2nd_session.testbed,lock_hold_locks_already_send_lock_2nd_session.device))
        lock_hold_locks_already_send_lock_2nd_session.nxos2 = ncssh.SshConnect(host.host_ip(lock_hold_locks_already_send_lock_2nd_session.testbed,lock_hold_locks_already_send_lock_2nd_session.device))
        try :
            lock_hold_locks_already_send_lock_2nd_session.message = command.lock_request('running')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def lock_test(self):
        self.obj = object()
        try :
            sessionid1=lock_hold_locks_already_send_lock_2nd_session.nxos1.nc_sshconnect(username=host.username(lock_hold_locks_already_send_lock_2nd_session.testbed,lock_hold_locks_already_send_lock_2nd_session.device),password=host.password(lock_hold_locks_already_send_lock_2nd_session.testbed,lock_hold_locks_already_send_lock_2nd_session.device))
            logging.info ('session-id is %s' %(sessionid1))
            response =lock_hold_locks_already_send_lock_2nd_session.nxos1._send(lock_hold_locks_already_send_lock_2nd_session.message,1)
            logging.info ('response is %s' % (response))
            logging.info ('lock acquired from this session with session-id %s' %(sessionid1))
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('lock request Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        
        try :
            sessionid2=lock_hold_locks_already_send_lock_2nd_session.nxos2.nc_sshconnect(username=host.username(lock_hold_locks_already_send_lock_2nd_session.testbed,lock_hold_locks_already_send_lock_2nd_session.device),password=host.password(lock_hold_locks_already_send_lock_2nd_session.testbed,lock_hold_locks_already_send_lock_2nd_session.device))
            logging.info ('session-id is %s' %(sessionid2))
            response =lock_hold_locks_already_send_lock_2nd_session.nxos2._send(lock_hold_locks_already_send_lock_2nd_session.message,0)
            logging.info ('response is %s' % (response))
            logging.info ('lock acquired from this session with session-id %s' %(sessionid2))
            int_value=Passed.code
            assert int_value == 1
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string)
            if error_list[1]=='lock-denied' and error_list[3]=='Lock Failed, lock is already held' and error_list[4] == sessionid1 :
                logging.info ('Lock is already acquired from the session with id %s' %(sessionid1))
                int_value=Passed.code   
                assert int_value == 1 
            else :
                logging.error ('Incorrect error returned')
                int_value=Failed.code
                assert int_value == 1
    
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            unlock_message = command.unlock_request('running')
            respone = lock_hold_locks_already_send_lock_2nd_session.nxos1._send(unlock_message,1)
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        finally :
            close_message = lock_hold_locks_already_send_lock_2nd_session.nxos1.closesession() 
            close_message = lock_hold_locks_already_send_lock_2nd_session.nxos2.closesession() 
            int_value=Passed.code
            assert int_value == 1  

class lock_sends_unlock_without_lock(aetest.Testcase):

    logging.info  ("This testcase sends unlock request without acquiring lock from the session")
    
    @aetest.setup
    def setup(self,testbed,device):
        self.obj = object()
        lock_sends_unlock_without_lock.testbed = testbed
        lock_sends_unlock_without_lock.device = device
        lock_sends_unlock_without_lock.nxos = ncssh.SshConnect(host.host_ip(lock_sends_unlock_without_lock.testbed,lock_sends_unlock_without_lock.device))
        try :
            lock_sends_unlock_without_lock.message = command.unlock_request('running')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def lock_test(self):
        self.obj = object()
        try :
            sessionid=lock_sends_unlock_without_lock.nxos.nc_sshconnect(username=host.username(lock_sends_unlock_without_lock.testbed,lock_sends_unlock_without_lock.device),password=host.password(lock_sends_unlock_without_lock.testbed,lock_sends_unlock_without_lock.device))
            logging.info ('session-id is %s' %(sessionid))
            response =lock_sends_unlock_without_lock.nxos._send(lock_sends_unlock_without_lock.message,0)
            logging.info ('response is %s' % (response))
        finally :
            error_response = ncssh._stripdelim(response)
            error_list = []
            root = ET.fromstring(error_response)
    
            error_type = root[0][0].text
            error_list.append(error_type)
    
            error_tag = root[0][1].text
            error_list.append(error_tag)      
    
            error_severity = root[0][2].text
            error_list.append(error_severity)
    
            error_message = root[0][3].text
            error_list.append(error_message)
    
            if error_list[1]=='unlock-denied' and error_list[3]=='Unlock Failed, lock is not held by this session' :
                logging.info ('Unlock denied as lock is not held by this session')
                int_value=Passed.code   
                assert int_value == 1 
            else :
                logging.error ('Incorrect error returned')
                int_value=Failed.code
                assert int_value == 1
                
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = lock_sends_unlock_without_lock.nxos.closesession() 
        int_value=Passed.code
        assert int_value == 1                 
                
class lock_kill_session_check_lock_removed(aetest.Testcase):
    
    logging.info  ("This testcase kills the session after acquiring lock and checks if lock is removed")

    @aetest.setup
    def setup(self,testbed,device):
        self.obj = object()
        lock_kill_session_check_lock_removed.testbed = testbed
        lock_kill_session_check_lock_removed.device = device
        lock_kill_session_check_lock_removed.nxos1 = ncssh.SshConnect(host.host_ip(lock_kill_session_check_lock_removed.testbed,lock_kill_session_check_lock_removed.device))
        lock_kill_session_check_lock_removed.nxos2 = ncssh.SshConnect(host.host_ip(lock_kill_session_check_lock_removed.testbed,lock_kill_session_check_lock_removed.device))
        try :
            lock_kill_session_check_lock_removed.message = command.lock_request('running')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def lock_test(self):
        self.obj = object()
        try :
            sessionid1=lock_kill_session_check_lock_removed.nxos1.nc_sshconnect(username=host.username(lock_kill_session_check_lock_removed.testbed,lock_kill_session_check_lock_removed.device),password=host.password(lock_kill_session_check_lock_removed.testbed,lock_kill_session_check_lock_removed.device))
            logging.info ('session-id is %s' %(sessionid1))
            sessionid2=lock_kill_session_check_lock_removed.nxos2.nc_sshconnect(username=host.username(lock_kill_session_check_lock_removed.testbed,lock_kill_session_check_lock_removed.device),password=host.password(lock_kill_session_check_lock_removed.testbed,lock_kill_session_check_lock_removed.device))
            logging.info ('session-id is %s' %(sessionid2))
            
            response =lock_kill_session_check_lock_removed.nxos2._send(lock_kill_session_check_lock_removed.message,1)
            logging.info ('lock acquired on running config from session with id %s' %(sessionid2))
            
            response =lock_kill_session_check_lock_removed.nxos1._send(command.kill_session(sessionid2),1)
            logging.info ('Netconf session with session id %s is killed' %(sessionid2))
            
            #sending a configure command to check if lock is removed
            output=nexus.nxos_config(d,'vlan 10',0)
            
            if output == 'None' :
                logging.info ('lock is removed')
            else :
                logging.error ('lock is not removed')
            logging.info ('output is %s' %(output))
            logging.info ('response is %s' % (response))
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('lock request Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = lock_kill_session_check_lock_removed.nxos1.closesession() 
        nexus.nxos_config(d,'no vlan 10',0)
        int_value=Passed.code
        assert int_value == 1            

class lock_send_cmd_to_cli_after_lock_through_netconf(aetest.Testcase):

    logging.info  ("This testcase sends config command to cli after lock is acquired through netconf session")
    
    @aetest.setup
    def setup(self,testbed,device):
        self.obj = object()
        lock_send_cmd_to_cli_after_lock_through_netconf.testbed = testbed
        lock_send_cmd_to_cli_after_lock_through_netconf.device = device
        lock_send_cmd_to_cli_after_lock_through_netconf.nxos = ncssh.SshConnect(host.host_ip(lock_send_cmd_to_cli_after_lock_through_netconf.testbed,lock_send_cmd_to_cli_after_lock_through_netconf.device))
        try :
            lock_send_cmd_to_cli_after_lock_through_netconf.message = command.lock_request('running')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def lock_test(self):
        self.obj = object()
        try :
            sessionid=lock_send_cmd_to_cli_after_lock_through_netconf.nxos.nc_sshconnect(username=host.username(lock_send_cmd_to_cli_after_lock_through_netconf.testbed,lock_send_cmd_to_cli_after_lock_through_netconf.device),password=host.password(lock_send_cmd_to_cli_after_lock_through_netconf.testbed,lock_send_cmd_to_cli_after_lock_through_netconf.device))
            logging.info ('session-id is %s' %(sessionid))
            
            response =lock_send_cmd_to_cli_after_lock_through_netconf.nxos._send(lock_send_cmd_to_cli_after_lock_through_netconf.message,1)
            logging.info ('lock acquired on running config from session with id %s' %(sessionid))
            
            #sending a configure command to check if lock is removed
            output=nexus.nxos_exec(d,'config')
            logging.info ('config command response is %s' % (output))
            
            if  re.match('Configuration locked. Feature-set operation in progress.',output) :
                logging.info ('switch returned:Configuration locked. Feature-set operation in progress.')
                int_value=Passed.code
                assert int_value == 1 
            else :
                int_value=Failed.code
                assert int_value == 1
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('lock request Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
            
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            unlock_message = command.unlock_request('running')
            respone = lock_send_cmd_to_cli_after_lock_through_netconf.nxos._send(unlock_message,1)
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        finally :
            close_message = lock_send_cmd_to_cli_after_lock_through_netconf.nxos.closesession() 
            int_value=Passed.code
            assert int_value == 1
            
class lock_netconf_timeout(aetest.Testcase):

    logging.info  ("This testcase tests lets the netconf session timeout and checks the lock is lost after session timeout")
    
    @aetest.setup
    def setup(self,testbed,device,config_file,config_file_dir,unconfig_file):
        self.obj = object()
        lock_netconf_timeout.testbed = testbed
        lock_netconf_timeout.device = device
        lock_netconf_timeout.nxos = ncssh.SshConnect(host.host_ip(lock_netconf_timeout.testbed,lock_netconf_timeout.device))

        #config file from which config has to be sent  
        config=config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        lock_netconf_timeout.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        lock_netconf_timeout.unconfig_file=config_file_dir+unconfig_file
        try :
            lock_netconf_timeout.message = command.lock_request('running')
            logging.info ('set the xml server timeout in the switch to 20 seconds')
            output=nexus.nxos_config(d,'xml server timeout 20',0)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def lock_test(self):
        self.obj = object()
        try :
            sessionid=lock_netconf_timeout.nxos.nc_sshconnect(username=host.username(lock_netconf_timeout.testbed,lock_netconf_timeout.device),password=host.password(lock_netconf_timeout.testbed,lock_netconf_timeout.device),command_timeout=20)
            logging.info ('session-id is %s' %(sessionid))
            response =lock_netconf_timeout.nxos._send(lock_netconf_timeout.message,1)
            logging.info ('response is %s' % (response))
            logging.info ('sending command to switch to check if the ssh connection still exists')
            #send_line =  'sleep 10 ; '+'show xml server status | grep ' + sessionid 
            send_line =  'show xml server status | grep ' + sessionid 
            output=nexus.nxos_exec(d,send_line)
            while sessionid in output :
                output=nexus.nxos_exec(d,send_line)    
            else :
                logging.info ('Netconf Session has timed out session id :' + sessionid)
            time.sleep(10)
            nexus.nxos_config(d,lock_netconf_timeout.config,0)
            nexus.verify_default_op(d,lock_netconf_timeout.config,'merge')
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.RunConfigError :
            logging.error ('Config not applied after session with lock is timedout')
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('lock request Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = lock_netconf_timeout.nxos.closesession()
        nexus.nxos_config(d,'xml server timeout 1200',0)
        nexus.nxos_unconfig(d,lock_netconf_timeout.unconfig_file)
        int_value=Passed.code
        assert int_value == 1 
            
class lock_config_send_editconfig_request(aetest.Testcase):

    logging.info  ("This testcase tests locks the config and sends edit-config request from another session")
    
    @aetest.setup
    def setup(self,testbed,device,config_file,config_file_dir):
        self.obj = object()
        lock_config_send_editconfig_request.testbed = testbed
        lock_config_send_editconfig_request.device = device
        lock_config_send_editconfig_request.nxos1 = ncssh.SshConnect(host.host_ip(lock_config_send_editconfig_request.testbed,lock_config_send_editconfig_request.device))
        lock_config_send_editconfig_request.nxos2 = ncssh.SshConnect(host.host_ip(lock_config_send_editconfig_request.testbed,lock_config_send_editconfig_request.device))

        #config file from which config has to be sent  
        config=config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        config = command.cmd_req('edit-config',config_file)

        try :
            lock_config_send_editconfig_request.message=nexus.nxos_xmlin(d,lock_config_send_editconfig_request.device,config,'edit-config')
            lock_config_send_editconfig_request.message2 = command.lock_request('running')
            sessionid1=lock_config_send_editconfig_request.nxos1.nc_sshconnect(username=host.username(lock_config_send_editconfig_request.testbed,lock_config_send_editconfig_request.device),password=host.password(lock_config_send_editconfig_request.testbed,lock_config_send_editconfig_request.device))
            logging.info ('session-id is %s' %(sessionid1))
            response =lock_config_send_editconfig_request.nxos1._send(lock_config_send_editconfig_request.message2,1)
            logging.info ('lock is acquired from the session with id %s' %(sessionid1))
            int_value = Passed.code
            assert int_value == 1
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('lock request Failed due to RPC-error')
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def lock_test(self):
        self.obj = object()
        try :
            sessionid2=lock_config_send_editconfig_request.nxos2.nc_sshconnect(username=host.username(lock_config_send_editconfig_request.testbed,lock_config_send_editconfig_request.device),password=host.password(lock_config_send_editconfig_request.testbed,lock_config_send_editconfig_request.device))
            logging.info ('session-id is %s' %(sessionid2))
            response =lock_config_send_editconfig_request.nxos2._send(lock_config_send_editconfig_request.message,0)
            logging.info ('response is %s' % (response))
        finally :
            error_response = ncssh._stripdelim(response)
            error_list = []
            root = ET.fromstring(error_response)
    
            error_type = root[0][0].text
            error_list.append(error_type)
    
            error_tag = root[0][1].text
            error_list.append(error_tag)      
    
            error_severity = root[0][2].text
            error_list.append(error_severity)
    
            error_message = root[0][3].text
            error_list.append(error_message)
    
            if error_list[1]=='operation-failed' and error_list[3]=='Lock is active. Edit config is not allowed from this session' :
                logging.info ('edit-config is not allowed from this session as lock is active')
                int_value=Passed.code   
                assert int_value == 1 
            else :
                logging.error ('Incorrect error returned')
                int_value=Failed.code
                assert int_value == 1
     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            unlock_message = command.unlock_request('running')
            respone = lock_config_send_editconfig_request.nxos1._send(unlock_message,1)
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('unlock request Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        finally :
            close_message = lock_config_send_editconfig_request.nxos1.closesession() 
            close_message = lock_config_send_editconfig_request.nxos2.closesession() 
            int_value=Passed.code
            assert int_value == 1              
            
class lock_running_as_target0(aetest.Testcase):

    logging.info  ("This testcase closes the session after acquiring lock and checks if lock is removed")
    
    @aetest.setup
    def setup(self,testbed,device,config_file,config_file_dir,unconfig_file):
        self.obj = object()
        lock_running_as_target0.testbed = testbed
        lock_running_as_target0.device = device
        lock_running_as_target0.nxos = ncssh.SshConnect(host.host_ip(lock_running_as_target0.testbed,lock_running_as_target0.device))

        #config file from which config has to be sent  
        config=config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        lock_running_as_target0.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        lock_running_as_target0.unconfig_file=config_file_dir+unconfig_file

        try :
            lock_running_as_target0.message = command.lock_request('running')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def lock_test(self):
        self.obj = object()
        try :
            sessionid=lock_running_as_target0.nxos.nc_sshconnect(username=host.username(lock_running_as_target0.testbed,lock_running_as_target0.device),password=host.password(lock_running_as_target0.testbed,lock_running_as_target0.device))
            logging.info ('session-id is %s' %(sessionid))
            
            response =lock_running_as_target0.nxos._send(lock_running_as_target0.message)
            logging.info ('response is %s' % (response))
            logging.info ('lock acquired on running config from session with id %s' %(sessionid))
            logging.info ('closing the session with lock on running config')
            lock_running_as_target0.nxos.closesession()
            #check if session is closed 
            send_line = 'show xml server status | grep '+sessionid
            output=nexus.nxos_exec(d,send_line)
            if re.match ('\s+',output) :
                logging.info ('session with sessionid %s is closed' %(sessionid))
            else :
                logging.error ('session with sessionid %s is not closed' %(sessionid))
                int_value=Failed.code
                assert int_value == 1
            #sending a configure command to check if lock is removed
            nexus.nxos_config(d,lock_running_as_target0.config,0)
            nexus.verify_default_op(d,lock_running_as_target0.config,'merge')
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.RunConfigError :
            logging.error ('Config not applied after session with lock is removed')
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('lock request Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        nexus.nxos_unconfig(d,lock_running_as_target0.unconfig_file)
        int_value=Passed.code
        assert int_value == 1            

class lock_running_as_target1(aetest.Testcase):
    
    logging.info  ("This testcase tests locks the config and sends copy-config request from another session")
    
    @aetest.setup
    def setup(self,testbed,device):
        self.obj = object()
        lock_running_as_target1.testbed = testbed
        lock_running_as_target1.device = device
        lock_running_as_target1.nxos1 = ncssh.SshConnect(host.host_ip(lock_running_as_target1.testbed,lock_running_as_target1.device))
        lock_running_as_target1.nxos2 = ncssh.SshConnect(host.host_ip(lock_running_as_target1.testbed,lock_running_as_target1.device))
        try :
            nexus.nxos_exec(d,'copy running-config abc.cfg')
            lock_running_as_target1.message=command.copy_config(1,1,'abc.cfg','running')
            lock_running_as_target1.message2 = command.lock_request('running')
            sessionid1=lock_running_as_target1.nxos1.nc_sshconnect(username=host.username(lock_running_as_target1.testbed,lock_running_as_target1.device),password=host.password(lock_running_as_target1.testbed,lock_running_as_target1.device))
            logging.info ('session-id is %s' %(sessionid1))
            response =lock_running_as_target1.nxos1._send(lock_running_as_target1.message2,1)
            logging.info ('lock is acquired from the session with id %s' %(sessionid1))
            int_value = Passed.code
            assert int_value == 1
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('lock request Failed due to RPC-error')
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def lock_test(self):
        self.obj = object()
        try :
            sessionid2=lock_running_as_target1.nxos2.nc_sshconnect(username=host.username(lock_running_as_target1.testbed,lock_running_as_target1.device),password=host.password(lock_running_as_target1.testbed,lock_running_as_target1.device))
            logging.info ('session-id is %s' %(sessionid2))
            response =lock_running_as_target1.nxos2._send(lock_running_as_target1.message,0)
            logging.info ('response is %s' % (response))
        finally :
            error_response = ncssh._stripdelim(response)
            error_list = []
            root = ET.fromstring(error_response)
    
            error_type = root[0][0].text
            error_list.append(error_type)
    
            error_tag = root[0][1].text
            error_list.append(error_tag)      
    
            error_severity = root[0][2].text
            error_list.append(error_severity)
    
            error_message = root[0][3].text
            error_list.append(error_message)
    
            if error_list[1]=='operation-failed' and error_list[3]=='Lock is active. copy-config not allowed from this session' :
                logging.info ('copy-config is not allowed from this session as lock is active')
                int_value=Passed.code   
                assert int_value == 1 
            else :
                logging.error ('Incorrect error returned')
                int_value=Failed.code
                assert int_value == 1
     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            unlock_message = command.unlock_request('running')
            respone = lock_running_as_target1.nxos1._send(unlock_message,1)
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('unlock request Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        finally :
            close_message = lock_running_as_target1.nxos1.closesession() 
            close_message = lock_running_as_target1.nxos2.closesession() 
            int_value=Passed.code
            assert int_value == 1   
            
class lock_running_as_target2(aetest.Testcase):
    
    logging.info  ("This testcase tests locks the config and sends get request from another session")
    
    @aetest.setup
    def setup(self,testbed,device):
        self.obj = object()
        lock_running_as_target2.testbed = testbed
        lock_running_as_target2.device = device
        lock_running_as_target2.nxos1 = ncssh.SshConnect(host.host_ip(lock_running_as_target2.testbed,lock_running_as_target2.device))
        lock_running_as_target2.nxos2 = ncssh.SshConnect(host.host_ip(lock_running_as_target2.testbed,lock_running_as_target2.device))
        try :
            lock_running_as_target2.message1 = nexus.nxos_xmlin (d,lock_running_as_target2.device,'show vlan','get')
            lock_running_as_target2.message2 = command.lock_request('running')
            sessionid1=lock_running_as_target2.nxos1.nc_sshconnect(username=host.username(lock_running_as_target2.testbed,lock_running_as_target2.device),password=host.password(lock_running_as_target2.testbed,lock_running_as_target2.device))
            logging.info ('session-id is %s' %(sessionid1))
            response =lock_running_as_target2.nxos1._send(lock_running_as_target2.message2,1)
            logging.info ('lock is acquired from the session with id %s' %(sessionid1))
            int_value = Passed.code
            assert int_value == 1
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('lock request Failed due to RPC-error')
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def lock_test(self):
        self.obj = object()
        try :
            sessionid2=lock_running_as_target2.nxos2.nc_sshconnect(username=host.username(lock_running_as_target2.testbed,lock_running_as_target2.device),password=host.password(lock_running_as_target2.testbed,lock_running_as_target2.device))
            logging.info ('session-id is %s' %(sessionid2))
            response =lock_running_as_target2.nxos2._send(lock_running_as_target2.message1)
            logging.info ('response is %s' % (response))
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.ShowError:
            int_value=Failed.code
            assert int_value == 1
     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            unlock_message = command.unlock_request('running')
            respone = lock_running_as_target2.nxos1._send(unlock_message,1)
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('unlock request Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        finally :
            close_message = lock_running_as_target2.nxos1.closesession() 
            close_message = lock_running_as_target2.nxos2.closesession() 
            int_value=Passed.code
            assert int_value == 1 

class default_op_none(aetest.Testcase):
    
    logging.info ('This testcase tests default option in edit-config as none')

    @aetest.setup
    def setup(self,testbed,device,config_file,config_file_dir):
        self.obj = object()
        default_op_none.testbed = testbed
        default_op_none.device = device
        default_op_none.nxos = ncssh.SshConnect(host.host_ip(default_op_none.testbed,default_op_none.device))
        
        #config file from which config has to be sent  
        config=config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        default_op_none.config = command.cmd_req('edit-config',config_file)
        try :
            default_op_none.message=nexus.nxos_xmlin(d,default_op_none.device,default_op_none.config,'edit-config')
            default_op_none.request=command.parse_req_default(default_op_none.message,"default-operation","none")
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def default_operation_test(self):
        self.obj = object()
        try :
            sessionid=default_op_none.nxos.nc_sshconnect(username=host.username(default_op_none.testbed,default_op_none.device),password=host.password(default_op_none.testbed,default_op_none.device))
            logging.info ('session-id is %s' %(sessionid))
            response =default_op_none.nxos._send(default_op_none.request)
            logging.info ('response is %s' % (response))
            nexus.verify_default_op(d,default_op_none.config,'none')
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
           
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = default_op_none.nxos.closesession() 
        int_value=Passed.code
        assert int_value == 1 

class default_op_merge(aetest.Testcase):
    
    logging.info ('This testcase tests default option in edit-config as merge')

    @aetest.setup
    def setup(self,testbed,device,config_file,config_file_dir,unconfig_file):
        self.obj = object()
        default_op_merge.testbed = testbed
        default_op_merge.device = device
        default_op_merge.nxos = ncssh.SshConnect(host.host_ip(default_op_merge.testbed,default_op_merge.device))
        #config file from which config has to be sent  
        config=config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        default_op_merge.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        default_op_merge.unconfig_file=config_file_dir+unconfig_file
        
        try :
            default_op_merge.message=nexus.nxos_xmlin(d,default_op_merge.device,default_op_merge.config,'edit-config')
            default_op_merge.request=command.parse_req_default(default_op_merge.message,"default-operation","merge")
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def default_operation_test(self):
        self.obj = object()
        try :
            sessionid=default_op_merge.nxos.nc_sshconnect(username=host.username(default_op_merge.testbed,default_op_merge.device),password=host.password(default_op_merge.testbed,default_op_merge.device))
            logging.info ('session-id is %s' %(sessionid))
            response =default_op_merge.nxos._send(default_op_merge.request)
            logging.info ('response is %s' % (response))
            nexus.verify_default_op(d,default_op_merge.config,'merge')
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
           
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = default_op_merge.nxos.closesession()
        nexus.nxos_unconfig(d,default_op_merge.unconfig_file)
        int_value=Passed.code
        assert int_value == 1

class default_op_replace(aetest.Testcase):

    logging.info ('This testcase tests default option in edit-config as replace')

    @aetest.setup
    def setup(self,testbed,device,config_file,config_file_dir):
        self.obj = object()
        default_op_replace.testbed = testbed
        default_op_replace.device = device
        default_op_replace.nxos = ncssh.SshConnect(host.host_ip(default_op_replace.testbed,default_op_replace.device))
        #config file from which config has to be sent  
        config=config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        config = command.cmd_req('edit-config',config_file)
        try :
            default_op_replace.message=nexus.nxos_xmlin(d,default_op_replace.device,config,'edit-config')
            default_op_replace.request=command.parse_req_default(default_op_replace.message,"default-operation","replace")
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def default_operation_test(self):
        self.obj = object()
        try :
            sessionid=default_op_replace.nxos.nc_sshconnect(username=host.username(default_op_replace.testbed,default_op_replace.device),password=host.password(default_op_replace.testbed,default_op_replace.device),command_timeout=120)
            logging.info ('session-id is %s' %(sessionid))
            response =default_op_replace.nxos._send(default_op_replace.request,0)
            logging.info ('response is %s' % (response))
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string)
            if error_list[1]=='operation-not-supported' and error_list[3]=='Currently not supported' and error_list[4] == 'default-operation' :
                logging.info ('Currently replace in default is not supported')
                int_value=Passed.code   
                assert int_value == 1 
            else :
                logging.debug ('Incorrect error returned')
                int_value=Failed.code
                assert int_value == 1
           
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = default_op_replace.nxos.closesession() 
        int_value=Passed.code
        assert int_value == 1 
        
class operation_merge(aetest.Testcase):

    logging.info ('This testcase tests option as merge for one command')

    @aetest.setup
    def setup(self,testbed,device,config_file,config_file_dir,unconfig_file):
        self.obj = object()
        operation_merge.testbed = testbed
        operation_merge.device = device
        operation_merge.nxos = ncssh.SshConnect(host.host_ip(operation_merge.testbed,operation_merge.device))
        #config file from which config has to be sent  
        config=config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        operation_merge.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        operation_merge.unconfig_file=config_file_dir+unconfig_file
        try :
            operation_merge.message=nexus.nxos_xmlin(d,operation_merge.device,operation_merge.config,'edit-config')
            op_dict = {'1':'merge','2':'merge'}
            operation_merge.request=command.parse_req_op(operation_merge.message,**op_dict)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def operation_test(self):
        self.obj = object()
        try :
            sessionid=operation_merge.nxos.nc_sshconnect(username=host.username(operation_merge.testbed,operation_merge.device),password=host.password(operation_merge.testbed,operation_merge.device),command_timeout=120)
            logging.info ('session-id is %s' %(sessionid))
            response =operation_merge.nxos._send(operation_merge.request)
            cmd_dict = {'1':'merge','2':'merge'}
            nexus.verify_op(d,operation_merge.config,**cmd_dict)
            logging.info ('response is %s' % (response))
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
           
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = operation_merge.nxos.closesession() 
        nexus.nxos_unconfig(d,operation_merge.unconfig_file)
        int_value=Passed.code
        assert int_value == 1 
        
class operation_delete(aetest.Testcase):
    logging.info ('This testcase tests option as delete for one command')

    @aetest.setup
    def setup(self,testbed,device,config_file,config_file_dir,unconfig_file):
        self.obj = object()
        operation_delete.testbed = testbed
        operation_delete.device = device
        operation_delete.nxos = ncssh.SshConnect(host.host_ip(operation_delete.testbed,operation_delete.device))
        #config file from which config has to be sent  
        config=config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        operation_delete.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        operation_delete.unconfig_file=config_file_dir+unconfig_file
        try :
            operation_delete.message=nexus.nxos_xmlin(d,operation_delete.device,operation_delete.config,'edit-config')
            op_dict = {'4':'delete','5':'delete'}
            operation_delete.request=command.parse_req_op(operation_delete.message,**op_dict)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def operation_test(self):
        self.obj = object()
        try :
            sessionid=operation_delete.nxos.nc_sshconnect(username=host.username(operation_delete.testbed,operation_delete.device),password=host.password(operation_delete.testbed,operation_delete.device),command_timeout=120)
            logging.info ('session-id is %s' %(sessionid))
            response =operation_delete.nxos._send(operation_delete.request)
            cmd_dict = {'4':'delete','5':'delete'}
            nexus.verify_op(d,operation_delete.config,**cmd_dict)
            logging.info ('response is %s' % (response))
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
           
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = operation_delete.nxos.closesession() 
        nexus.nxos_unconfig(d,operation_delete.unconfig_file)
        int_value=Passed.code
        assert int_value == 1 
        
class operation_merge_delete(aetest.Testcase):

    logging.info ('This testcase tests option as merge for one command and delete for other command')

    @aetest.setup
    def setup(self,testbed,device,config_file,config_file_dir,unconfig_file):
        self.obj = object()
        operation_merge_delete.testbed = testbed
        operation_merge_delete.device = device
        operation_merge_delete.nxos = ncssh.SshConnect(host.host_ip(operation_merge_delete.testbed,operation_merge_delete.device))
        #config file from which config has to be sent  
        config=config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        operation_merge_delete.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        operation_merge_delete.unconfig_file=config_file_dir+unconfig_file
        try :
            operation_merge_delete.message=nexus.nxos_xmlin(d,operation_merge_delete.device,operation_merge_delete.config,'edit-config')
            op_dict = {'2':'merge','4':'delete'}
            operation_merge_delete.request=command.parse_req_op(operation_merge_delete.message,**op_dict)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def operation_test(self):
        self.obj = object()
        try :
            sessionid=operation_merge_delete.nxos.nc_sshconnect(username=host.username(operation_merge_delete.testbed,operation_merge_delete.device),password=host.password(operation_merge_delete.testbed,operation_merge_delete.device),command_timeout=120)
            logging.info ('session-id is %s' %(sessionid))
            response =operation_merge_delete.nxos._send(operation_merge_delete.request)
            cmd_dict = {'2':'merge','4':'delete'}
            nexus.verify_op(d,operation_merge_delete.config,**cmd_dict)
            logging.info ('response is %s' % (response))
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
           
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = operation_merge_delete.nxos.closesession() 
        nexus.nxos_unconfig(d,operation_merge_delete.unconfig_file)
        int_value=Passed.code
        assert int_value == 1 
        
class operation_merge_defaultoption_none(aetest.Testcase):

    logging.info ('This testcase tests default option in edit-config as none and option as merge for one command')
    
    @aetest.setup
    def setup(self,testbed,device,config_file,config_file_dir,unconfig_file):
        self.obj = object()
        operation_merge_defaultoption_none.testbed = testbed
        operation_merge_defaultoption_none.device = device
        operation_merge_defaultoption_none.nxos = ncssh.SshConnect(host.host_ip(operation_merge_defaultoption_none.testbed,operation_merge_defaultoption_none.device))

        #config file from which config has to be sent  
        config=config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        operation_merge_defaultoption_none.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        operation_merge_defaultoption_none.unconfig_file=config_file_dir+unconfig_file
        try :
            operation_merge_defaultoption_none.message=nexus.nxos_xmlin(d,operation_merge_defaultoption_none.device,operation_merge_defaultoption_none.config,'edit-config')
            request=command.parse_req_default(operation_merge_defaultoption_none.message,"default-operation","none")
            cmd_dict={'1':'merge','2':'merge'}
            operation_merge_defaultoption_none.request=command.parse_req_op(request,**cmd_dict)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def operation_test(self):
        self.obj = object()
        try :
            sessionid=operation_merge_defaultoption_none.nxos.nc_sshconnect(username=host.username(operation_merge_defaultoption_none.testbed,operation_merge_defaultoption_none.device),password=host.password(operation_merge_defaultoption_none.testbed,operation_merge_defaultoption_none.device),command_timeout=120)
            logging.info ('session-id is %s' %(sessionid))
            response =operation_merge_defaultoption_none.nxos._send(operation_merge_defaultoption_none.request)
            logging.info ('response is %s' % (response))
            cmd_dict={'1':'merge','2':'merge'}
            nexus.verify_op(d,operation_merge_defaultoption_none.config,**cmd_dict)
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError :
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
           
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = operation_merge_defaultoption_none.nxos.closesession()
        nexus.nxos_unconfig(d,operation_merge_defaultoption_none.unconfig_file) 
        int_value=Passed.code
        assert int_value == 1
        
class operation_delete_defaultoption_none(aetest.Testcase):

    logging.info ('This testcase tests default option in edit-config as none and option as delete for other command')
    
    @aetest.setup
    def setup(self,testbed,device,config_file,config_file_dir,unconfig_file):
        self.obj = object()
        operation_delete_defaultoption_none.testbed = testbed
        operation_delete_defaultoption_none.device = device
        operation_delete_defaultoption_none.nxos = ncssh.SshConnect(host.host_ip(operation_delete_defaultoption_none.testbed,operation_delete_defaultoption_none.device))

        #config file from which config has to be sent  
        config=config_file

        operation_delete_defaultoption_none.config_file = config_file_dir+config

        #getting the configuration from the config file
        operation_delete_defaultoption_none.config = command.cmd_req('edit-config',operation_delete_defaultoption_none.config_file)

        #unconfig file to be sent in the cleanup
        operation_delete_defaultoption_none.unconfig_file=config_file_dir+unconfig_file
        try :
            operation_delete_defaultoption_none.message=nexus.nxos_xmlin(d,operation_delete_defaultoption_none.device,operation_delete_defaultoption_none.config,'edit-config')
            request=command.parse_req_default(operation_delete_defaultoption_none.message,"default-operation","none")
            cmd_dict = {'1':'delete'}
            operation_delete_defaultoption_none.request=command.parse_req_op(request,**cmd_dict)
            #configure a command on switch 
            nexus.nxos_config(d,operation_delete_defaultoption_none.config_file)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def operation_test(self):
        self.obj = object()
        try :
            sessionid=operation_delete_defaultoption_none.nxos.nc_sshconnect(username=host.username(operation_delete_defaultoption_none.testbed,operation_delete_defaultoption_none.device),password=host.password(operation_delete_defaultoption_none.testbed,operation_delete_defaultoption_none.device),command_timeout=120)
            logging.info ('session-id is %s' %(sessionid))
            response =operation_delete_defaultoption_none.nxos._send(operation_delete_defaultoption_none.request)
            logging.info ('response is %s' % (response))
            cmd_dict={'1':'delete'}
            nexus.verify_op(d,operation_delete_defaultoption_none.config,**cmd_dict)
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError :
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
           
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = operation_delete_defaultoption_none.nxos.closesession()
        nexus.nxos_unconfig(d,operation_delete_defaultoption_none.unconfig_file)
        int_value=Passed.code
        assert int_value == 1
        
class operation_merge_delete_defaultoption_none(aetest.Testcase):

    logging.info ('This testcase tests default option in edit-config as none and option as merge for one command and delete for other command')
    
    @aetest.setup
    def setup(self,testbed,device,config_file,config_file_dir,unconfig_file):
        self.obj = object()
        operation_merge_delete_defaultoption_none.testbed = testbed
        operation_merge_delete_defaultoption_none.device = device
        operation_merge_delete_defaultoption_none.nxos = ncssh.SshConnect(host.host_ip(operation_merge_delete_defaultoption_none.testbed,operation_merge_delete_defaultoption_none.device))
        #config file from which config has to be sent  
        config=config_file

        operation_merge_delete_defaultoption_none.config_file = config_file_dir+config

        #getting the configuration from the config file
        operation_merge_delete_defaultoption_none.config = command.cmd_req('edit-config',operation_merge_delete_defaultoption_none.config_file)

        #unconfig file to be sent in the cleanup
        operation_merge_delete_defaultoption_none.unconfig_file=config_file_dir+unconfig_file
        try :
            operation_merge_delete_defaultoption_none.message=nexus.nxos_xmlin(d,operation_merge_delete_defaultoption_none.device,operation_merge_delete_defaultoption_none.config,'edit-config')
            request=command.parse_req_default(operation_merge_delete_defaultoption_none.message,"default-operation","none")
            cmd_dict = {'1':'merge','2':'merge','3':'delete'}
            operation_merge_delete_defaultoption_none.request=command.parse_req_op(request,**cmd_dict)
            #configure a command on switch 
            nexus.nxos_config(d,'interface port-channel 2121',0)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def operation_test(self):
        self.obj = object()
        try :
            sessionid=operation_merge_delete_defaultoption_none.nxos.nc_sshconnect(username=host.username(operation_merge_delete_defaultoption_none.testbed,operation_merge_delete_defaultoption_none.device),password=host.password(operation_merge_delete_defaultoption_none.testbed,operation_merge_delete_defaultoption_none.device),command_timeout=120)
            logging.info ('session-id is %s' %(sessionid))
            response =operation_merge_delete_defaultoption_none.nxos._send(operation_merge_delete_defaultoption_none.request)
            logging.info ('response is %s' % (response))
            cmd_dict={'1':'merge','2':'merge','3':'delete'}
            nexus.verify_op(d,operation_merge_delete_defaultoption_none.config,**cmd_dict)
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError :
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
           
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = operation_merge_delete_defaultoption_none.nxos.closesession()
        nexus.nxos_unconfig(d,operation_merge_delete_defaultoption_none.unconfig_file)
        int_value=Passed.code
        assert int_value == 1


class candidate_commit(aetest.Testcase):

    logging.info  ("This testcase tests the candidate option with commit")
    
    @aetest.setup
    def setup(self,testbed,device,netconf_config_file,config_file_dir,unconfig_file):
        self.obj = object()
        candidate_commit.testbed = testbed
        candidate_commit.device = device
        candidate_commit.nxos = ncssh.SshConnect(host.host_ip(candidate_commit.testbed,candidate_commit.device))
        
        #config file from which config has to be sent as candidate config 
        config=netconf_config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        candidate_commit.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        candidate_commit.unconfig_file=config_file_dir+unconfig_file
        try :
            message = nexus.nxos_xmlin(d,candidate_commit.device,candidate_commit.config,'edit-config')
            candidate_commit.message = command.build_candidate(message)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def candidate_test(self):
        self.obj = object()
        try :
            sessionid=candidate_commit.nxos.nc_sshconnect(username=host.username(candidate_commit.testbed,candidate_commit.device),password=host.password(candidate_commit.testbed,candidate_commit.device))
            logging.info ('session-id is %s' %(sessionid))
            logging.info ('sending candidate config request to the switch')

            #sending candidate config to the switch 
            response =candidate_commit.nxos._send(candidate_commit.message,1)
            logging.info ('response is %s' % (response))

            #check that candidate config is not applied to switch before sending commit 
            nexus.verify_default_op(d,candidate_commit.config,'none')
            logging.info('candidate config is not yet applied to switch')

            #sending candidate commit
            message = command.build_candidate_commit()
            logging.info ('sending candidate config commit to the switch')
            response =candidate_commit.nxos._send(message,1)
            logging.info ('response is %s' % (response))

            #checking if candidate config is applied after sending commit 
            nexus.verify_default_op(d,candidate_commit.config,'merge')
            logging.info('candidate config is applied to switch after sending commit')

            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('candidate Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            close_message = candidate_commit.nxos.closesession()
            nexus.nxos_unconfig(d,candidate_commit.unconfig_file)
            int_value=Passed.code
            assert int_value == 1  
        except nxos_XML_errors.NetConfRPCError :
            int_value=Failed.code
            assert int_value == 1

class candidate_discard_changes(aetest.Testcase):

    logging.info  ("This testcase tests the candidate option with discard changes")
    
    @aetest.setup
    def setup(self,testbed,device,netconf_config_file,config_file_dir,unconfig_file):
        self.obj = object()
        candidate_discard_changes.testbed = testbed
        candidate_discard_changes.device = device
        candidate_discard_changes.nxos = ncssh.SshConnect(host.host_ip(candidate_discard_changes.testbed,candidate_discard_changes.device))

        config=netconf_config_file
        config_file = config_file_dir+config

        candidate_discard_changes.config = command.cmd_req('edit-config',config_file)
        candidate_discard_changes.unconfig_file=config_file_dir+unconfig_file
        try :
            message = nexus.nxos_xmlin(d,candidate_discard_changes.device,candidate_discard_changes.config,'edit-config')
            candidate_discard_changes.message = command.build_candidate(message)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def candidate_test(self):
        self.obj = object()
        try :
            sessionid=candidate_discard_changes.nxos.nc_sshconnect(username=host.username(candidate_discard_changes.testbed,candidate_discard_changes.device),password=host.password(candidate_discard_changes.testbed,candidate_discard_changes.device))
            logging.info ('session-id is %s' %(sessionid))
            logging.info ('sending candidate config request to the switch')
            response =candidate_discard_changes.nxos._send(candidate_discard_changes.message,1)
            logging.info ('response is %s' % (response))
            message = command.build_candidate_discard()
            logging.info ('sending candidate config discard to the switch')
            response =candidate_discard_changes.nxos._send(message,1)
            logging.info ('response is %s' % (response))
            nexus.verify_default_op(d,candidate_discard_changes.config,'none')
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('candidate Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            close_message = candidate_discard_changes.nxos.closesession()
            int_value=Passed.code
            assert int_value == 1  
        except nxos_XML_errors.NetConfRPCError :
            int_value=Failed.code
            assert int_value == 1

class candidate_commit_without_candidate_config(aetest.Testcase):

    logging.info  ("This testcase tests the commit without sending candidate config")
    
    @aetest.setup
    def setup(self,testbed,device,netconf_config_file,config_file_dir,unconfig_file):
        self.obj = object()
        candidate_commit_without_candidate_config.testbed = testbed
        candidate_commit_without_candidate_config.device = device
        candidate_commit_without_candidate_config.nxos = ncssh.SshConnect(host.host_ip(candidate_commit_without_candidate_config.testbed,candidate_commit_without_candidate_config.device))
        try :
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def candidate_test(self):
        self.obj = object()
        try :
            message = command.build_candidate_commit()
            sessionid=candidate_commit_without_candidate_config.nxos.nc_sshconnect(username=host.username(candidate_commit_without_candidate_config.testbed,candidate_commit_without_candidate_config.device),password=host.password(candidate_commit_without_candidate_config.testbed,candidate_commit_without_candidate_config.device))
            logging.info ('session-id is %s' %(sessionid))
            logging.info ('sending candidate config commit to the switch')
            response =candidate_commit_without_candidate_config.nxos._send(message,0)
            logging.info ('response is %s' % (response))
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('candidate Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string,0)
            if error_list[1] == "operation-failed" and error_list[3]== "Candidate configuration is disabled.Please enable and try again" :
                int_value=Passed.code
                assert int_value == 1 
            else :
                logging.error('incorrect error returned')
                int_value=Failed.code
                assert int_value == 1
                
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            close_message = candidate_commit_without_candidate_config.nxos.closesession()
            int_value=Passed.code
            assert int_value == 1  
        except nxos_XML_errors.NetConfRPCError :
            int_value=Failed.code
            assert int_value == 1

class candidate_discard_without_candidate_config(aetest.Testcase):

    logging.info  ("This testcase tests the discard without sending candidate config")
    
    @aetest.setup
    def setup(self,testbed,device,netconf_config_file,config_file_dir,unconfig_file):
        self.obj = object()
        candidate_discard_without_candidate_config.testbed = testbed
        candidate_discard_without_candidate_config.device = device
        candidate_discard_without_candidate_config.nxos = ncssh.SshConnect(host.host_ip(candidate_discard_without_candidate_config.testbed,candidate_discard_without_candidate_config.device))
        try :
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def candidate_test(self):
        self.obj = object()
        try :
            message = command.build_candidate_discard()
            sessionid=candidate_discard_without_candidate_config.nxos.nc_sshconnect(username=host.username(candidate_discard_without_candidate_config.testbed,candidate_discard_without_candidate_config.device),password=host.password(candidate_discard_without_candidate_config.testbed,candidate_discard_without_candidate_config.device))
            logging.info ('session-id is %s' %(sessionid))
            logging.info ('sending candidate config commit to the switch')
            response =candidate_discard_without_candidate_config.nxos._send(message,0)
            logging.info ('response is %s' % (response))
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('candidate Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string,0)
            if error_list[1] == "operation-failed" and error_list[3]== "Candidate configuration is disabled.Please enable and try again" :
                int_value=Passed.code
                assert int_value == 1 
            else :
                logging.error('incorrect error returned')
                int_value=Failed.code
                assert int_value == 1
                
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            close_message = candidate_discard_without_candidate_config.nxos.closesession()
            int_value=Passed.code
            assert int_value == 1  
        except nxos_XML_errors.NetConfRPCError :
            int_value=Failed.code
            assert int_value == 1

class candidate_commit_with_errored_config(aetest.Testcase):

    logging.info  ("This testcase tests the candidate option with commit with errored configuration")
    
    @aetest.setup
    def setup(self,testbed,device,error_file,config_file_dir,unconfig_file):
        self.obj = object()
        candidate_commit_with_errored_config.testbed = testbed
        candidate_commit_with_errored_config.device = device
        candidate_commit_with_errored_config.nxos = ncssh.SshConnect(host.host_ip(candidate_commit_with_errored_config.testbed,candidate_commit_with_errored_config.device))
        
        #config file from which config has to be sent as candidate config 
        config=error_file

        config_file = config_file_dir+config

        candidate_commit_with_errored_config.config = command.cmd_req('edit-config',config_file)
        #unconfig file to be sent in the cleanup
        candidate_commit_with_errored_config.unconfig_file=config_file_dir+unconfig_file
        try :
            message = nexus.nxos_xmlin(d,candidate_commit_with_errored_config.device,candidate_commit_with_errored_config.config,'edit-config')

            #injecting error into configuration
            err_dict = {'4':'0'}
    
            request = command.build_error(message,**err_dict)
            candidate_commit_with_errored_config.message = command.build_candidate(request)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def candidate_test(self):
        self.obj = object()
        try :
            sessionid=candidate_commit_with_errored_config.nxos.nc_sshconnect(username=host.username(candidate_commit_with_errored_config.testbed,candidate_commit_with_errored_config.device),password=host.password(candidate_commit_with_errored_config.testbed,candidate_commit_with_errored_config.device))
            logging.info ('session-id is %s' %(sessionid))
            logging.info ('sending candidate config request to the switch')

            #sending candidate config to the switch 
            response =candidate_commit_with_errored_config.nxos._send(candidate_commit_with_errored_config.message)
            logging.info ('response is %s' % (response))

            #check that candidate config is not applied to switch before sending commit 
            nexus.verify_default_op(d,candidate_commit_with_errored_config.config,'none')
            logging.info('candidate config is not yet applied to switch')

            #sending candidate commit
            message = command.build_candidate_commit()
            logging.info ('sending candidate config commit to the switch')
            response_2 =candidate_commit_with_errored_config.nxos._send(message,0)
            logging.info ('response is %s' % (response_2))

            #checking if candidate config is applied after sending commit 
            args = ['4']
            nexus.verify_error(d,candidate_commit_with_errored_config.config,'stop',*args)
            logging.info('candidate config is applied to switch after sending commit')

        except nxos_XML_errors.NetConfRPCError:
            logging.error ('candidate Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
        finally :
            error_string = ncssh._stripdelim(response_2)
            error_list=ncssh.rpc_error(error_string,0)
            if error_list[1] == "invalid-value" :
                int_value=Passed.code
                assert int_value == 1 
            else :
                logging.error('incorrect error returned')
                int_value=Failed.code
                assert int_value == 1       
     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            close_message = candidate_commit_with_errored_config.nxos.closesession()
            nexus.nxos_unconfig(d,candidate_commit_with_errored_config.unconfig_file)
            int_value=Passed.code
            assert int_value == 1  
        except nxos_XML_errors.NetConfRPCError :
            int_value=Failed.code
            assert int_value == 1
class candidate_default_option_none(aetest.Testcase):

    logging.info  ("This testcase tests the candidate with default-option as none")
    
    @aetest.setup
    def setup(self,testbed,device,netconf_config_file,config_file_dir,unconfig_file):
        self.obj = object()
        candidate_default_option_none.testbed = testbed
        candidate_default_option_none.device = device
        candidate_default_option_none.nxos = ncssh.SshConnect(host.host_ip(candidate_default_option_none.testbed,candidate_default_option_none.device))
        
        #config file from which config has to be sent as candidate config 
        config=netconf_config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        candidate_default_option_none.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        candidate_default_option_none.unconfig_file=config_file_dir+unconfig_file
        try :
            message = nexus.nxos_xmlin(d,candidate_default_option_none.device,candidate_default_option_none.config,'edit-config')
            
            request = command.parse_req_default(message,"default-operation","none")
            candidate_default_option_none.message = command.build_candidate(request)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def candidate_test(self):
        self.obj = object()
        try :
            sessionid=candidate_default_option_none.nxos.nc_sshconnect(username=host.username(candidate_default_option_none.testbed,candidate_default_option_none.device),password=host.password(candidate_default_option_none.testbed,candidate_default_option_none.device))
            logging.info ('session-id is %s' %(sessionid))
            logging.info ('sending candidate config request to the switch')

            #sending candidate config to the switch 
            response =candidate_default_option_none.nxos._send(candidate_default_option_none.message)
            logging.info ('response is %s' % (response))

            #check that candidate config is not applied to switch before sending commit 
            nexus.verify_default_op(d,candidate_default_option_none.config,'none')
            logging.info('candidate config is not yet applied to switch')

            #send candidate commit 
            message = command.build_candidate_commit()
            logging.info ('sending candidate config commit to the switch')
            response_2 = candidate_default_option_none.nxos._send(message)

            #verify that the config is not present in the running
            nexus.verify_default_op(d,candidate_default_option_none.config,'none')
            logging.info('config is not pushed to running config after sending commit')

        except nxos_XML_errors.NetConfRPCError:
            logging.error ('candidate Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            close_message = candidate_default_option_none.nxos.closesession()
            nexus.nxos_unconfig(d,candidate_default_option_none.unconfig_file)
            int_value=Passed.code
            assert int_value == 1  
        except nxos_XML_errors.NetConfRPCError :
            int_value=Failed.code
            assert int_value == 1


class candidate_default_option_merge(aetest.Testcase):

    logging.info  ("This testcase tests the candidate with default-option as merge")
    
    @aetest.setup
    def setup(self,testbed,device,netconf_config_file,config_file_dir,unconfig_file):
        self.obj = object()
        candidate_default_option_merge.testbed = testbed
        candidate_default_option_merge.device = device
        candidate_default_option_merge.nxos = ncssh.SshConnect(host.host_ip(candidate_default_option_merge.testbed,candidate_default_option_merge.device))
        
        #config file from which config has to be sent as candidate config 
        config=netconf_config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        candidate_default_option_merge.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        candidate_default_option_merge.unconfig_file=config_file_dir+unconfig_file
        try :
            message = nexus.nxos_xmlin(d,candidate_default_option_merge.device,candidate_default_option_merge.config,'edit-config')
            
            request = command.parse_req_default(message,"default-operation","merge")
            candidate_default_option_merge.message = command.build_candidate(request)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def candidate_test(self):
        self.obj = object()
        try :
            sessionid=candidate_default_option_merge.nxos.nc_sshconnect(username=host.username(candidate_default_option_merge.testbed,candidate_default_option_merge.device),password=host.password(candidate_default_option_merge.testbed,candidate_default_option_merge.device))
            logging.info ('session-id is %s' %(sessionid))
            logging.info ('sending candidate config request to the switch')

            #sending candidate config to the switch 
            response =candidate_default_option_merge.nxos._send(candidate_default_option_merge.message,0)
            logging.info ('response is %s' % (response))

            #check that candidate config is not applied to switch before sending commit 
            nexus.verify_default_op(d,candidate_default_option_merge.config,'none')
            logging.info('candidate config is not yet applied to switch')

            #send candidate commit 
            message = command.build_candidate_commit()
            logging.info ('sending candidate config commit to the switch')
            response_2 = candidate_default_option_merge.nxos._send(message)

            #verify that the configuration is done on the switch
            nexus.verify_default_op(d,candidate_default_option_merge.config,'merge')

        except nxos_XML_errors.NetConfRPCError:
            logging.error ('candidate Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1      
     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            close_message = candidate_default_option_merge.nxos.closesession()
            nexus.nxos_unconfig(d,candidate_default_option_merge.unconfig_file)
            int_value=Passed.code
            assert int_value == 1  
        except nxos_XML_errors.NetConfRPCError :
            int_value=Failed.code
            assert int_value == 1

class candidate_test_then_set(aetest.Testcase):

    logging.info  ("This testcase tests the candidate with test-option as test-then-set")
    
    @aetest.setup
    def setup(self,testbed,device,netconf_config_file,config_file_dir,unconfig_file):
        self.obj = object()
        candidate_test_then_set.testbed = testbed
        candidate_test_then_set.device = device
        candidate_test_then_set.nxos = ncssh.SshConnect(host.host_ip(candidate_test_then_set.testbed,candidate_test_then_set.device))        
        #config file from which config has to be sent as candidate config 
        config=netconf_config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        candidate_test_then_set.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        candidate_test_then_set.unconfig_file=config_file_dir+unconfig_file
        try :
            message = nexus.nxos_xmlin(d,candidate_test_then_set.device,candidate_test_then_set.config,'edit-config')
            
            request = command.test_option(message,"test-then-set")
            candidate_test_then_set.message = command.build_candidate(request)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def candidate_test(self):
        self.obj = object()
        try :
            sessionid=candidate_test_then_set.nxos.nc_sshconnect(username=host.username(candidate_test_then_set.testbed,candidate_test_then_set.device),password=host.password(candidate_test_then_set.testbed,candidate_test_then_set.device))
            logging.info ('session-id is %s' %(sessionid))
            logging.info ('sending candidate config request to the switch')

            #sending candidate config to the switch 
            response =candidate_test_then_set.nxos._send(candidate_test_then_set.message,0)
            logging.info ('response is %s' % (response))

            #check that candidate config is not applied to switch before sending commit 
            nexus.verify_default_op(d,candidate_test_then_set.config,'none')
            logging.info('candidate config is not yet applied to switch')

        except nxos_XML_errors.NetConfRPCError:
            logging.error ('candidate Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string,0)
            if error_list[1] == "invalid-value" and error_list[3] == "Candidate datastore does not support this operation" :
                int_value=Passed.code
                assert int_value == 1 
            else :
                logging.error('incorrect error returned')
                int_value=Failed.code
                assert int_value == 1       
     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            close_message = candidate_test_then_set.nxos.closesession()
            nexus.nxos_unconfig(d,candidate_test_then_set.unconfig_file)
            int_value=Passed.code
            assert int_value == 1  
        except nxos_XML_errors.NetConfRPCError :
            int_value=Failed.code
            assert int_value == 1

class candidate_set(aetest.Testcase):

    logging.info  ("This testcase tests the candidate with test-option as set")
    
    @aetest.setup
    def setup(self,testbed,device,netconf_config_file,config_file_dir,unconfig_file):
        self.obj = object()
        candidate_set.testbed = testbed
        candidate_set.device = device
        candidate_set.nxos = ncssh.SshConnect(host.host_ip(candidate_set.testbed,candidate_set.device))       
        #config file from which config has to be sent as candidate config 
        config=netconf_config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        candidate_set.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        candidate_set.unconfig_file=config_file_dir+unconfig_file
        try :
            message = nexus.nxos_xmlin(d,candidate_set.device,candidate_set.config,'edit-config')
            
            request = command.test_option(message,"set")
            candidate_set.message = command.build_candidate(request)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def candidate_test(self):
        self.obj = object()
        try :
            sessionid=candidate_set.nxos.nc_sshconnect(username=host.username(candidate_set.testbed,candidate_set.device),password=host.password(candidate_set.testbed,candidate_set.device))
            logging.info ('session-id is %s' %(sessionid))
            logging.info ('sending candidate config request to the switch')

            #sending candidate config to the switch 
            response =candidate_set.nxos._send(candidate_set.message,0)
            logging.info ('response is %s' % (response))

            #check that candidate config is not applied to switch before sending commit 
            nexus.verify_default_op(d,candidate_set.config,'none')
            logging.info('candidate config is not yet applied to switch')

        except nxos_XML_errors.NetConfRPCError:
            logging.error ('candidate Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string,0)
            if error_list[1] == "invalid-value" and error_list[3] == "Candidate datastore does not support this operation" :
                int_value=Passed.code
                assert int_value == 1 
            else :
                logging.error('incorrect error returned')
                int_value=Failed.code
                assert int_value == 1       
     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            close_message = candidate_set.nxos.closesession()
            nexus.nxos_unconfig(d,candidate_set.unconfig_file)
            int_value=Passed.code
            assert int_value == 1  
        except nxos_XML_errors.NetConfRPCError :
            int_value=Failed.code
            assert int_value == 1

class candidate_commit_stop_on_error(aetest.Testcase):

    logging.info  ("This testcase tests the candidate with error-option as stop-on-error")
    
    @aetest.setup
    def setup(self,testbed,device,netconf_config_file,config_file_dir,unconfig_file):
        self.obj = object()
        candidate_commit_stop_on_error.testbed = testbed
        candidate_commit_stop_on_error.device = device
        candidate_commit_stop_on_error.nxos = ncssh.SshConnect(host.host_ip(candidate_commit_stop_on_error.testbed,candidate_commit_stop_on_error.device))        
        #config file from which config has to be sent as candidate config 
        config=netconf_config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        candidate_commit_stop_on_error.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        candidate_commit_stop_on_error.unconfig_file=config_file_dir+unconfig_file
        try :
            message = nexus.nxos_xmlin(d,candidate_commit_stop_on_error.device,candidate_commit_stop_on_error.config,'edit-config')
            
            request = command.error_option(message,"stop-on-error")
            candidate_commit_stop_on_error.message = command.build_candidate(request)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def candidate_test(self):
        self.obj = object()
        try :
            sessionid=candidate_commit_stop_on_error.nxos.nc_sshconnect(username=host.username(candidate_commit_stop_on_error.testbed,candidate_commit_stop_on_error.device),password=host.password(candidate_commit_stop_on_error.testbed,candidate_commit_stop_on_error.device))
            logging.info ('session-id is %s' %(sessionid))
            logging.info ('sending candidate config request to the switch')

            #sending candidate config to the switch 
            response =candidate_commit_stop_on_error.nxos._send(candidate_commit_stop_on_error.message,0)
            logging.info ('response is %s' % (response))

            #check that candidate config is not applied to switch before sending commit 
            nexus.verify_default_op(d,candidate_commit_stop_on_error.config,'none')
            logging.info('candidate config is not yet applied to switch')

        except nxos_XML_errors.NetConfRPCError:
            logging.error ('candidate Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string,0)
            if error_list[1] == "invalid-value" and error_list[3] == "Candidate datastore does not support this operation" :
                int_value=Passed.code
                assert int_value == 1 
            else :
                logging.error('incorrect error returned')
                int_value=Failed.code
                assert int_value == 1       
     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            close_message = candidate_commit_stop_on_error.nxos.closesession()
            nexus.nxos_unconfig(d,candidate_commit_stop_on_error.unconfig_file)
            int_value=Passed.code
            assert int_value == 1  
        except nxos_XML_errors.NetConfRPCError :
            int_value=Failed.code
            assert int_value == 1


class candidate_commit_continue_on_error(aetest.Testcase):

    logging.info  ("This testcase tests the candidate with error-option as continue-on-error")
    
    @aetest.setup
    def setup(self,testbed,device,netconf_config_file,config_file_dir,unconfig_file):
        self.obj = object()
        candidate_commit_continue_on_error.testbed = testbed
        candidate_commit_continue_on_error.device = device
        candidate_commit_continue_on_error.nxos = ncssh.SshConnect(host.host_ip(candidate_commit_continue_on_error.testbed,candidate_commit_continue_on_error.device))        
        #config file from which config has to be sent as candidate config 
        config=netconf_config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        candidate_commit_continue_on_error.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        candidate_commit_continue_on_error.unconfig_file=config_file_dir+unconfig_file
        try :
            message = nexus.nxos_xmlin(d,candidate_commit_continue_on_error.device,candidate_commit_continue_on_error.config,'edit-config')
            
            request = command.error_option(message,"continue-on-error")
            candidate_commit_continue_on_error.message = command.build_candidate(request)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def candidate_test(self):
        self.obj = object()
        try :
            sessionid=candidate_commit_continue_on_error.nxos.nc_sshconnect(username=host.username(candidate_commit_continue_on_error.testbed,candidate_commit_continue_on_error.device),password=host.password(candidate_commit_continue_on_error.testbed,candidate_commit_continue_on_error.device))
            logging.info ('session-id is %s' %(sessionid))
            logging.info ('sending candidate config request to the switch')

            #sending candidate config to the switch 
            response =candidate_commit_continue_on_error.nxos._send(candidate_commit_continue_on_error.message,0)
            logging.info ('response is %s' % (response))

            #check that candidate config is not applied to switch before sending commit 
            nexus.verify_default_op(d,candidate_commit_continue_on_error.config,'none')
            logging.info('candidate config is not yet applied to switch')

        except nxos_XML_errors.NetConfRPCError:
            logging.error ('candidate Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string,0)
            if error_list[1] == "invalid-value" and error_list[3] == "Candidate datastore does not support this operation" :
                int_value=Passed.code
                assert int_value == 1 
            else :
                logging.error('incorrect error returned')
                int_value=Failed.code
                assert int_value == 1       
     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            close_message = candidate_commit_continue_on_error.nxos.closesession()
            nexus.nxos_unconfig(d,candidate_commit_continue_on_error.unconfig_file)
            int_value=Passed.code
            assert int_value == 1  
        except nxos_XML_errors.NetConfRPCError :
            int_value=Failed.code
            assert int_value == 1


class candidate_commit_rollback_on_error(aetest.Testcase):

    logging.info  ("This testcase tests the candidate with error-option as rollback-on-error")
    
    @aetest.setup
    def setup(self,testbed,device,netconf_config_file,config_file_dir,unconfig_file):
        self.obj = object()
        candidate_commit_rollback_on_error.testbed = testbed
        candidate_commit_rollback_on_error.device = device
        candidate_commit_rollback_on_error.nxos = ncssh.SshConnect(host.host_ip(candidate_commit_rollback_on_error.testbed,candidate_commit_rollback_on_error.device))        
        #config file from which config has to be sent as candidate config 
        config=netconf_config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        candidate_commit_rollback_on_error.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        candidate_commit_rollback_on_error.unconfig_file=config_file_dir+unconfig_file
        try :
            message = nexus.nxos_xmlin(d,candidate_commit_rollback_on_error.device,candidate_commit_rollback_on_error.config,'edit-config')
            
            request = command.error_option(message,"rollback-on-error")
            candidate_commit_rollback_on_error.message = command.build_candidate(request)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def candidate_test(self):
        self.obj = object()
        try :
            sessionid=candidate_commit_rollback_on_error.nxos.nc_sshconnect(username=host.username(candidate_commit_rollback_on_error.testbed,candidate_commit_rollback_on_error.device),password=host.password(candidate_commit_rollback_on_error.testbed,candidate_commit_rollback_on_error.device))
            logging.info ('session-id is %s' %(sessionid))
            logging.info ('sending candidate config request to the switch')

            #sending candidate config to the switch 
            response =candidate_commit_rollback_on_error.nxos._send(candidate_commit_rollback_on_error.message,0)
            logging.info ('response is %s' % (response))

            #check that candidate config is not applied to switch before sending commit 
            nexus.verify_default_op(d,candidate_commit_rollback_on_error.config,'none')
            logging.info('candidate config is not yet applied to switch')

        except nxos_XML_errors.NetConfRPCError:
            logging.error ('candidate Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string,0)
            if error_list[1] == "invalid-value" and error_list[3] == "Candidate datastore does not support this operation" :
                int_value=Passed.code
                assert int_value == 1 
            else :
                logging.error('incorrect error returned')
                int_value=Failed.code
                assert int_value == 1       
     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            close_message = candidate_commit_rollback_on_error.nxos.closesession()
            nexus.nxos_unconfig(d,candidate_commit_rollback_on_error.unconfig_file)
            int_value=Passed.code
            assert int_value == 1  
        except nxos_XML_errors.NetConfRPCError :
            int_value=Failed.code
            assert int_value == 1

class candidate_replace(aetest.Testcase):

    logging.info  ("This testcase tests the candidate_replace option against the candidate ")
    
    @aetest.setup
    def setup(self,testbed,device,netconf_config_file,config_file_dir,unconfig_file):
        self.obj = object()
        candidate_replace.testbed = testbed
        candidate_replace.device = device
        candidate_replace.nxos = ncssh.SshConnect(host.host_ip(candidate_replace.testbed,candidate_replace.device))

        #config file from which config has to be sent as candidate config 
        config=netconf_config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        candidate_replace.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        candidate_replace.unconfig_file=config_file_dir+unconfig_file
        
        try :
            message = nexus.nxos_xmlin(d,candidate_replace.device,candidate_replace.config,'edit-config')
            request=command.parse_req_default(message,'default-operation','replace')
            candidate_replace.message = command.build_candidate(request)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def replace_test(self):
        self.obj = object()
        try :
            candidate_replace.nxos.nc_sshconnect(username=host.username(candidate_replace.testbed,candidate_replace.device),password=host.password(candidate_replace.testbed,candidate_replace.device))
            response =candidate_replace.nxos._send(candidate_replace.message,0)
            logging.info ('response is %s' % (response))
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        finally:
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string)
            if error_list[1]=='operation-not-supported' and error_list[3]=='Currently not supported' and error_list[4] == 'default-operation' :
                logging.info ('candidate_replace is not supported')
                int_value=Passed.code
                assert int_value == 1
            else :
                logging.debug ('Incorrect error returned')

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            close_message = candidate_replace.nxos.closesession()
            nexus.nxos_unconfig(d,candidate_replace.unconfig_file)
            int_value=Passed.code
            assert int_value == 1  
        except nxos_XML_errors.NetConfRPCError :
            int_value=Failed.code
            assert int_value == 1

class candidate_validate_running_config_copied_to_file(aetest.Testcase):

    logging.info  ("This testcase tests the validate option against candidate config")
    
    @aetest.setup
    def setup(self,testbed,device,netconf_config_file,config_file_dir,unconfig_file):
        self.obj = object()
        candidate_validate_running_config_copied_to_file.testbed = testbed
        candidate_validate_running_config_copied_to_file.device = device
        candidate_validate_running_config_copied_to_file.nxos = ncssh.SshConnect(host.host_ip(candidate_validate_running_config_copied_to_file.testbed,candidate_validate_running_config_copied_to_file.device))
        #config file from which config has to be sent as candidate config 
        config=netconf_config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        candidate_validate_running_config_copied_to_file.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        candidate_validate_running_config_copied_to_file.unconfig_file=config_file_dir+unconfig_file
        try :
            #nexus.nxos_exec('copy run test.cfg')
            message = nexus.nxos_xmlin(d,candidate_validate_running_config_copied_to_file.device,candidate_validate_running_config_copied_to_file.config,'edit-config')
            candidate_validate_running_config_copied_to_file.message_1 = command.build_candidate(message)
            
            #building validate request with source as candidate
            candidate_validate_running_config_copied_to_file.message_2 = command.validate_req(source='candidate')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def validate_test(self):
        self.obj = object()
        try :
            sessionid=candidate_validate_running_config_copied_to_file.nxos.nc_sshconnect(username=host.username(candidate_validate_running_config_copied_to_file.testbed,candidate_validate_running_config_copied_to_file.device),password=host.password(candidate_validate_running_config_copied_to_file.testbed,candidate_validate_running_config_copied_to_file.device))
            logging.info ('session-id is %s' %(sessionid))
            logging.info ('sending candidate config request to the switch')

            #sending candidate config to the switch 
            response =candidate_validate_running_config_copied_to_file.nxos._send(candidate_validate_running_config_copied_to_file.message_1,1)
            logging.info ('response is %s' % (response))

            #check that candidate config is not applied to switch before sending commit 
            nexus.verify_default_op(d,candidate_validate_running_config_copied_to_file.config,'none')
            logging.info('candidate config is not yet applied to switch')

            logging.info ('sending candidate validate request to the switch')
            response =candidate_validate_running_config_copied_to_file.nxos._send(candidate_validate_running_config_copied_to_file.message_2,1)
            logging.info ('response is %s' % (response))
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = candidate_validate_running_config_copied_to_file.nxos.closesession() 
        int_value=Passed.code
        assert int_value == 1 


class candidate_validate_file_not_present_in_bootflash(aetest.Testcase):

    logging.info  ("This testcase tests the validate option against candidate config with errored config")

    @aetest.setup
    def setup(self,testbed,device,error_file,config_file_dir,unconfig_file):
        self.obj = object()
        candidate_validate_file_not_present_in_bootflash.testbed = testbed
        candidate_validate_file_not_present_in_bootflash.device = device
        candidate_validate_file_not_present_in_bootflash.nxos = ncssh.SshConnect(host.host_ip(candidate_validate_file_not_present_in_bootflash.testbed,candidate_validate_file_not_present_in_bootflash.device))
        #config file from which config has to be sent as candidate config 
        config=error_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        candidate_validate_file_not_present_in_bootflash.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        candidate_validate_file_not_present_in_bootflash.unconfig_file=config_file_dir+unconfig_file
        try :
            #nexus.nxos_exec('copy run test.cfg')
            message = nexus.nxos_xmlin(d,candidate_validate_file_not_present_in_bootflash.device,candidate_validate_file_not_present_in_bootflash.config,'edit-config')

            #injecting error into configuration
            err_dict = {'4':'0'}
            
            request = command.build_error(message,**err_dict)
            candidate_validate_file_not_present_in_bootflash.message_1 = command.build_candidate(request)
            
            #building validate request with source as candidate
            candidate_validate_file_not_present_in_bootflash.message_2 = command.validate_req(source='candidate')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def validate_test(self):
        self.obj = object()
        try :
            sessionid=candidate_validate_file_not_present_in_bootflash.nxos.nc_sshconnect(username=host.username(candidate_validate_file_not_present_in_bootflash.testbed,candidate_validate_file_not_present_in_bootflash.device),password=host.password(candidate_validate_file_not_present_in_bootflash.testbed,candidate_validate_file_not_present_in_bootflash.device))
            logging.info ('session-id is %s' %(sessionid))
            logging.info ('sending candidate config request to the switch')

            #sending candidate config to the switch 
            response =candidate_validate_file_not_present_in_bootflash.nxos._send(candidate_validate_file_not_present_in_bootflash.message_1,1)
            logging.info ('response is %s' % (response))

            #check that candidate config is not applied to switch before sending commit 
            nexus.verify_default_op(d,candidate_validate_file_not_present_in_bootflash.config,'none')
            logging.info('candidate config is not yet applied to switch')

            logging.info ('sending candidate validate request to the switch')
            response =candidate_validate_file_not_present_in_bootflash.nxos._send(candidate_validate_file_not_present_in_bootflash.message_2,0)
            logging.info ('response is %s' % (response))
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        finally:
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string)
            if error_list[1] == "invalid-value" and error_list[4]== "validate" :
                logging.info ('correct error returned')
                int_value=Passed.code
                assert int_value == 1
            else :
                logging.debug("Incorrect error returned")
                int_value=Failed.code
                assert int_value == 1

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = candidate_validate_file_not_present_in_bootflash.nxos.closesession() 
        int_value=Passed.code
        assert int_value == 1 

class candidate_copy_file(aetest.Testcase):

    logging.info  ("This testcase tests copy config from candidate datastore to file")
    
    @aetest.setup
    def setup(self,testbed,device,netconf_config_file,config_file_dir,unconfig_file):
        self.obj = object()
        candidate_copy_file.testbed = testbed
        candidate_copy_file.device = device
        candidate_copy_file.nxos = ncssh.SshConnect(host.host_ip(candidate_copy_file.testbed,candidate_copy_file.device))
        #config file from which config has to be sent as candidate config 
        config=netconf_config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        candidate_copy_file.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        candidate_copy_file.unconfig_file=config_file_dir+unconfig_file
        try :
            message = nexus.nxos_xmlin(d,candidate_copy_file.device,candidate_copy_file.config,'edit-config')
            candidate_copy_file.message_1 = command.build_candidate(message)
            
            #building copy config request with source as candidate
            candidate_copy_file.message_2 = command.copy_config_candidate('file://test.cfg',1)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def candidate_copy(self):
        self.obj = object()
        try :
            sessionid=candidate_copy_file.nxos.nc_sshconnect(username=host.username(candidate_copy_file.testbed,candidate_copy_file.device),password=host.password(candidate_copy_file.testbed,candidate_copy_file.device))
            logging.info ('session-id is %s' %(sessionid))
            logging.info ('sending candidate config request to the switch')

            #sending candidate config to the switch 
            response =candidate_copy_file.nxos._send(candidate_copy_file.message_1)
            logging.info ('response is %s' % (response))

            #check that candidate config is not applied to switch before sending commit 
            nexus.verify_default_op(d,candidate_copy_file.config,'none')
            logging.info('candidate config is not yet applied to switch')

            logging.info ('sending candidate copy request to the switch')
            response =candidate_copy_file.nxos._send(candidate_copy_file.message_2)
            logging.info ('response is %s' % (response))
            int_value=Passed.code
            assert int_value == 1
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = candidate_copy_file.nxos.closesession() 
        int_value=Passed.code
        assert int_value == 1 

class candidate_copy_file_to_candidate(aetest.Testcase):

    logging.info  ("This testcase copy config from file to candidate datastore")

    @aetest.setup
    def setup(self,testbed,device,netconf_config_file,config_file_dir,unconfig_file):
        self.obj = object()
        candidate_copy_file_to_candidate.testbed = testbed
        candidate_copy_file_to_candidate.device = device
        candidate_copy_file_to_candidate.nxos = ncssh.SshConnect(host.host_ip(candidate_copy_file_to_candidate.testbed,candidate_copy_file_to_candidate.device))
        #config file from which config has to be sent as candidate config 
        config=netconf_config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        candidate_copy_file_to_candidate.config = command.cmd_req('edit-config',config_file)

        #copying file from directory to bootflash of the device
        nexus.copy_file(candidate_copy_file_to_candidate.testbed,d,config_file)

        #unconfig file to be sent in the cleanup
        candidate_copy_file_to_candidate.unconfig_file=config_file_dir+unconfig_file
        try :
            #building validate request with source as candidate
            send_line = 'file://'+config
            candidate_copy_file_to_candidate.message_2 = command.copy_config_candidate(send_line,0)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def candidate_copy(self):
        self.obj = object()
        try :
            sessionid=candidate_copy_file_to_candidate.nxos.nc_sshconnect(username=host.username(candidate_copy_file_to_candidate.testbed,candidate_copy_file_to_candidate.device),password=host.password(candidate_copy_file_to_candidate.testbed,candidate_copy_file_to_candidate.device))
            logging.info ('session-id is %s' %(sessionid))
            logging.info ('sending candidate config request to the switch')

            logging.info ('sending candidate copy request to the switch')
            response =candidate_copy_file_to_candidate.nxos._send(candidate_copy_file_to_candidate.message_2)
            logging.info ('response is %s' % (response))

            #check that candidate config is not applied to switch
            nexus.verify_default_op(d,candidate_copy_file_to_candidate.config,'none')
            logging.info('candidate config is not yet applied to switch')

            #sending candidate commit
            message = command.build_candidate_commit()
            logging.info ('sending candidate config commit to the switch')
            response =candidate_copy_file_to_candidate.nxos._send(message,1)
            logging.info ('response is %s' % (response))


            int_value=Passed.code
            assert int_value == 1
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = candidate_copy_file_to_candidate.nxos.closesession() 
        nexus.nxos_unconfig(d,candidate_copy_file_to_candidate.unconfig_file)
        int_value=Passed.code
        assert int_value == 1

class candidate_copy_file_size_MB(aetest.Testcase):
    
    logging.info  ("This testcase tests copy config from file with size more than 0.4MB")
    
    @aetest.setup
    def setup(self,testbed,device,large_file,config_file_dir,unconfig_file):
        self.obj = object()
        candidate_copy_file_size_MB.testbed = testbed
        candidate_copy_file_size_MB.device = device
        candidate_copy_file_size_MB.nxos = ncssh.SshConnect(host.host_ip(candidate_copy_file_size_MB.testbed,candidate_copy_file_size_MB.device))
        try :
            #copying file from tftp location to device
            nexus.copy_file(candidate_copy_file_size_MB.testbed,d,config_file_dir+large_file)
            #building copy config request with source as file and target as candidate
            send_line = 'file://'+large_file
            candidate_copy_file_size_MB.message = command.copy_config_candidate(send_line,0)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def candidate_copy(self):
        self.obj = object()
        try :
            sessionid=candidate_copy_file_size_MB.nxos.nc_sshconnect(username=host.username(candidate_copy_file_size_MB.testbed,candidate_copy_file_size_MB.device),password=host.password(candidate_copy_file_size_MB.testbed,candidate_copy_file_size_MB.device))
            logging.info ('session-id is %s' %(sessionid))
            logging.info ('sending candidate config request to the switch')
            
            logging.info('sending copy config request for config file size greater than 0.4MB')
            response =candidate_copy_file_size_MB.nxos._send(candidate_copy_file_size_MB.message,0)
            logging.info ('response is %s' % (response))
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string,0)
            if error_list[1] == "too-big" and error_list[3]== "File size should not be more than 0.4 MB" :
                int_value=Passed.code
                assert int_value == 1 
            else :
                logging.error('incorrect error returned')
                int_value=Failed.code
                assert int_value == 1

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = candidate_copy_file_size_MB.nxos.closesession() 
        int_value=Passed.code
        assert int_value == 1 


class candidate_lock_running_as_target(aetest.Testcase):

    logging.info  ("This testcase tests the lock option with candidate as the target")
    
    @aetest.setup
    def setup(self,testbed,device,netconf_config_file,config_file_dir,unconfig_file):
        self.obj = object()
        candidate_lock_running_as_target.testbed = testbed
        candidate_lock_running_as_target.device = device
        candidate_lock_running_as_target.nxos = ncssh.SshConnect(host.host_ip(candidate_lock_running_as_target.testbed,candidate_lock_running_as_target.device))
        #config file from which config has to be sent as candidate config 
        config=netconf_config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        candidate_lock_running_as_target.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        candidate_lock_running_as_target.unconfig_file=config_file_dir+unconfig_file
        try :

            message = nexus.nxos_xmlin(d,candidate_lock_running_as_target.device,candidate_lock_running_as_target.config,'edit-config')
            candidate_lock_running_as_target.message_1 = command.build_candidate(message)

            #building lock request for candidate
            candidate_lock_running_as_target.message_2 = command.lock_request('candidate')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def lock_test(self):
        self.obj = object()

        try :
            sessionid=candidate_lock_running_as_target.nxos.nc_sshconnect(username=host.username(candidate_lock_running_as_target.testbed,candidate_lock_running_as_target.device),password=host.password(candidate_lock_running_as_target.testbed,candidate_lock_running_as_target.device))
            logging.info ('session-id is %s' %(sessionid))
            response =candidate_lock_running_as_target.nxos._send(candidate_lock_running_as_target.message_1)
            logging.info ('response is %s' % (response))
            response =candidate_lock_running_as_target.nxos._send(candidate_lock_running_as_target.message_2)
            logging.info ('response is %s' % (response))
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('lock request Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1

     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            unlock_message = command.unlock_request('candidate')
            respone = candidate_lock_running_as_target.nxos._send(unlock_message,1)
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('unlock request Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        finally :
            close_message = candidate_lock_running_as_target.nxos.closesession() 
            int_value=Passed.code
            assert int_value == 1  

class candidate_lock_startup_as_target(aetest.Testcase):

    logging.info  ("This testcase tests the lock option with candidate as the target without sending candidate config")
    
    @aetest.setup
    def setup(self,testbed,device,netconf_config_file,config_file_dir,unconfig_file):
        self.obj = object()
        candidate_lock_startup_as_target.testbed = testbed
        candidate_lock_startup_as_target.device = device
        candidate_lock_startup_as_target.nxos = ncssh.SshConnect(host.host_ip(candidate_lock_startup_as_target.testbed,candidate_lock_startup_as_target.device))
        try :

            #building lock request for candidate
            candidate_lock_startup_as_target.message = command.lock_request('candidate')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def lock_test(self):
        self.obj = object()
        try :
            sessionid=candidate_lock_startup_as_target.nxos.nc_sshconnect(username=host.username(candidate_lock_startup_as_target.testbed,candidate_lock_startup_as_target.device),password=host.password(candidate_lock_startup_as_target.testbed,candidate_lock_startup_as_target.device))
            logging.info ('session-id is %s' %(sessionid))
            response =candidate_lock_startup_as_target.nxos._send(candidate_lock_startup_as_target.message,0)
            logging.info ('response is %s' % (response)) 
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('lock request Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string,0)
            if error_list[1] == "operation-failed" and error_list[3]== "Candidate datastore is not available.Can't lock" :
                int_value=Passed.code
                assert int_value == 1 
            else :
                logging.error('incorrect error returned')
                int_value=Failed.code
                assert int_value == 1
     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            close_message = candidate_lock_startup_as_target.nxos.closesession() 
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1

class candidate_lock_hold_locks_already(aetest.Testcase):

    logging.info  ("This testcase tests the unlock option with candidate as the target without sending candidate config")
    
    @aetest.setup
    def setup(self,testbed,device,netconf_config_file,config_file_dir,unconfig_file):
        self.obj = object()
        candidate_lock_hold_locks_already.testbed = testbed
        candidate_lock_hold_locks_already.device = device
        candidate_lock_hold_locks_already.nxos = ncssh.SshConnect(host.host_ip(candidate_lock_hold_locks_already.testbed,candidate_lock_hold_locks_already.device))
        try :

            #building lock request for candidate
            candidate_lock_hold_locks_already.message = command.unlock_request('candidate')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def lock_test(self):
        self.obj = object()
        try :
            sessionid=candidate_lock_hold_locks_already.nxos.nc_sshconnect(username=host.username(candidate_lock_hold_locks_already.testbed,candidate_lock_hold_locks_already.device),password=host.password(candidate_lock_hold_locks_already.testbed,candidate_lock_hold_locks_already.device))
            logging.info ('session-id is %s' %(sessionid))
            response =candidate_lock_hold_locks_already.nxos._send(candidate_lock_hold_locks_already.message,0)
            logging.info ('response is %s' % (response)) 
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('lock request Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string,0)
            if error_list[1] == "operation-failed" and error_list[3]== "Candidate datastore is not available.Can't unlock." :
                int_value=Passed.code
                assert int_value == 1 
            else :
                logging.error('incorrect error returned')
                int_value=Failed.code
                assert int_value == 1
     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            close_message = candidate_lock_hold_locks_already.nxos.closesession() 
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1


class candidate_lock_hold_locks_already_send_lock_2nd_session(aetest.Testcase):

    logging.info  ("This testcase sends lock request for candidate from session which already has lock acquired on candidate config")
    
    @aetest.setup
    def setup(self,testbed,device,netconf_config_file,config_file_dir,unconfig_file):
        self.obj = object()
        candidate_lock_hold_locks_already_send_lock_2nd_session.testbed = testbed
        candidate_lock_hold_locks_already_send_lock_2nd_session.device = device
        candidate_lock_hold_locks_already_send_lock_2nd_session.nxos = ncssh.SshConnect(host.host_ip(candidate_lock_hold_locks_already_send_lock_2nd_session.testbed,candidate_lock_hold_locks_already_send_lock_2nd_session.device))
        #config file from which config has to be sent as candidate config 
        config=netconf_config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        candidate_lock_hold_locks_already_send_lock_2nd_session.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        candidate_lock_hold_locks_already_send_lock_2nd_session.unconfig_file=config_file_dir+unconfig_file
        try :

            message = nexus.nxos_xmlin(d,candidate_lock_hold_locks_already_send_lock_2nd_session.device,candidate_lock_hold_locks_already_send_lock_2nd_session.config,'edit-config')
            candidate_lock_hold_locks_already_send_lock_2nd_session.message_1 = command.build_candidate(message)

            #building lock request for candidate
            candidate_lock_hold_locks_already_send_lock_2nd_session.message_2 = command.lock_request('candidate')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def lock_test(self):
        self.obj = object()
        try :
            sessionid=candidate_lock_hold_locks_already_send_lock_2nd_session.nxos.nc_sshconnect(username=host.username(candidate_lock_hold_locks_already_send_lock_2nd_session.testbed,candidate_lock_hold_locks_already_send_lock_2nd_session.device),password=host.password(candidate_lock_hold_locks_already_send_lock_2nd_session.testbed,candidate_lock_hold_locks_already_send_lock_2nd_session.device))
            logging.info ('session-id is %s' %(sessionid))
            response =candidate_lock_hold_locks_already_send_lock_2nd_session.nxos._send(candidate_lock_hold_locks_already_send_lock_2nd_session.message_1)
            logging.info ('response is %s' % (response))
            response =candidate_lock_hold_locks_already_send_lock_2nd_session.nxos._send(candidate_lock_hold_locks_already_send_lock_2nd_session.message_2)
            logging.info ('response is %s' % (response))
            response =candidate_lock_hold_locks_already_send_lock_2nd_session.nxos._send(candidate_lock_hold_locks_already_send_lock_2nd_session.message_2,0)
            logging.info ('response is %s' % (response))
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('lock request Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string)
            if error_list[1] == "lock-denied" and error_list[3]== "Lock Failed, candidate lock is already held" and error_list[4]==sessionid :
                int_value=Passed.code
                assert int_value == 1 
            else :
                logging.error('incorrect error returned')
                int_value=Failed.code
                assert int_value == 1

     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            unlock_message = command.unlock_request('candidate')
            respone = candidate_lock_hold_locks_already_send_lock_2nd_session.nxos._send(unlock_message,1)
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('unlock request Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        finally :
            close_message = candidate_lock_hold_locks_already_send_lock_2nd_session.nxos.closesession() 
            int_value=Passed.code
            assert int_value == 1  


class candidate_lock_sends_unlock_without_lock(aetest.Testcase):

    logging.info  ("This testcase tests sends unlock from the session which has already unlocked the config")
    
    @aetest.setup
    def setup(self,testbed,device,netconf_config_file,config_file_dir,unconfig_file):
        self.obj = object()
        candidate_lock_sends_unlock_without_lock.testbed = testbed
        candidate_lock_sends_unlock_without_lock.device = device
        candidate_lock_sends_unlock_without_lock.nxos = ncssh.SshConnect(host.host_ip(candidate_lock_sends_unlock_without_lock.testbed,candidate_lock_sends_unlock_without_lock.device))
        #config file from which config has to be sent as candidate config 
        config=netconf_config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        candidate_lock_sends_unlock_without_lock.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        candidate_lock_sends_unlock_without_lock.unconfig_file=config_file_dir+unconfig_file
        try :

            message = nexus.nxos_xmlin(d,candidate_lock_sends_unlock_without_lock.device,candidate_lock_sends_unlock_without_lock.config,'edit-config')
            candidate_lock_sends_unlock_without_lock.message_1 = command.build_candidate(message)

            #building lock request for candidate
            candidate_lock_sends_unlock_without_lock.message_2 = command.lock_request('candidate')
            candidate_lock_sends_unlock_without_lock.message_3 = command.unlock_request('candidate')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def lock_test(self):
        self.obj = object()
        try :
            sessionid=candidate_lock_sends_unlock_without_lock.nxos.nc_sshconnect(username=host.username(candidate_lock_sends_unlock_without_lock.testbed,candidate_lock_sends_unlock_without_lock.device),password=host.password(candidate_lock_sends_unlock_without_lock.testbed,candidate_lock_sends_unlock_without_lock.device))
            logging.info ('session-id is %s' %(sessionid))
            response =candidate_lock_sends_unlock_without_lock.nxos._send(candidate_lock_sends_unlock_without_lock.message_1)
            logging.info ('response is %s' % (response))
            response =candidate_lock_sends_unlock_without_lock.nxos._send(candidate_lock_sends_unlock_without_lock.message_2)
            logging.info ('response is %s' % (response))
            response =candidate_lock_sends_unlock_without_lock.nxos._send(candidate_lock_sends_unlock_without_lock.message_3)
            logging.info ('response is %s' % (response))
            response =candidate_lock_sends_unlock_without_lock.nxos._send(candidate_lock_sends_unlock_without_lock.message_3,0)
            logging.info ('response is %s' % (response))
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('lock request Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string,0)
            if error_list[1] == "lock-denied" and error_list[3]== "Unlock Failed, candidate datastore is not locked"  :
                int_value=Passed.code
                assert int_value == 1 
            else :
                logging.error('incorrect error returned')
                int_value=Failed.code
                assert int_value == 1

     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            close_message = candidate_lock_sends_unlock_without_lock.nxos.closesession() 
            int_value=Passed.code
            assert int_value == 1  
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1

class candidate_url(aetest.Testcase):

    logging.info  ("This testcase tests the edit-config with url as source")
    
    @aetest.setup
    def setup(self,testbed,device,config_file,config_file_dir,unconfig_file):
        self.obj = object()
        candidate_url.testbed = testbed
        candidate_url.device = device
        candidate_url.nxos = ncssh.SshConnect(host.host_ip(candidate_url.testbed,candidate_url.device))
        
        #config file from which has to be sent as source in url 
        config=config_file

        config_file = config_file_dir+config
        candidate_url.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        candidate_url.unconfig_file=config_file_dir+unconfig_file
        try :
            #copying file from directory to bootflash of the device
            nexus.copy_file(candidate_url.testbed,d,config_file)
            candidate_url.message = command.candidate_url(d,candidate_url.device,config)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def candidate_url(self):
        self.obj = object()
        try :
            sessionid=candidate_url.nxos.nc_sshconnect(username=host.username(candidate_url.testbed,candidate_url.device),password=host.password(candidate_url.testbed,candidate_url.device),command_timeout=500)
            logging.info ('session-id is %s' %(sessionid))
            logging.info ('sending edit config with url request to the switch')

            #sending edit config to the switch 
            response =candidate_url.nxos._send(candidate_url.message,1)
            logging.info ('response is %s' % (response))

            nexus.verify_default_op(d,candidate_url.config,'none')

            #sending candidate commit
            message = command.build_candidate_commit()
            logging.info ('sending candidate config commit to the switch')
            response =candidate_url.nxos._send(message,1)
            logging.info ('response is %s' % (response))

            #checking if candidate config is applied after sending commit 
            nexus.verify_default_op(d,candidate_url.config,'merge')
            logging.info('candidate config is applied to switch after sending commit')
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('edit config Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            close_message = candidate_url.nxos.closesession()
            nexus.nxos_unconfig(d,candidate_url.unconfig_file)
            int_value=Passed.code
            assert int_value == 1  
        except nxos_XML_errors.NetConfRPCError :
            int_value=Failed.code
            assert int_value == 1

class candidate_operation_merge(aetest.Testcase):

    logging.info ('This testcase tests operation as merge for one command')

    @aetest.setup
    def setup(self,testbed,device,netconf_config_file,config_file_dir,unconfig_file):
        self.obj = object()
        candidate_operation_merge.testbed = testbed
        candidate_operation_merge.device = device
        candidate_operation_merge.nxos = ncssh.SshConnect(host.host_ip(candidate_operation_merge.testbed,candidate_operation_merge.device))
        #config file from which config has to be sent as candidate config 
        config=netconf_config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        candidate_operation_merge.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        candidate_operation_merge.unconfig_file=config_file_dir+unconfig_file
        try :
            candidate_operation_merge.message=nexus.nxos_xmlin(d,candidate_operation_merge.device,candidate_operation_merge.config,'edit-config')
            op_dict = {'1':'merge'}
            request=command.parse_req_op(candidate_operation_merge.message,**op_dict)
            candidate_operation_merge.request = command.build_candidate(request)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def operation_test(self):
        self.obj = object()
        try :
            sessionid=candidate_operation_merge.nxos.nc_sshconnect(username=host.username(candidate_operation_merge.testbed,candidate_operation_merge.device),password=host.password(candidate_operation_merge.testbed,candidate_operation_merge.device),command_timeout=120)
            logging.info ('session-id is %s' %(sessionid))
            response =candidate_operation_merge.nxos._send(candidate_operation_merge.request)

            #send candidate commit to switch
            request = command.build_candidate_commit()
            logging.info('sending candidate commit')
            response_2 = candidate_operation_merge.nxos._send(request)
            logging.info('response is '+response_2)

            cmd_dict = {'1':'merge'}
            nexus.verify_op(d,candidate_operation_merge.config,**cmd_dict)
            logging.info ('response is %s' % (response))
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
           
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = candidate_operation_merge.nxos.closesession() 
        nexus.nxos_unconfig(d,candidate_operation_merge.unconfig_file)
        int_value=Passed.code
        assert int_value == 1 

class candidate_default_none_op_merge(aetest.Testcase):

    logging.info ('This testcase tests default option as none with operation as merge for one command')

    @aetest.setup
    def setup(self,testbed,device,netconf_config_file,config_file_dir,unconfig_file):
        self.obj = object()
        candidate_default_none_op_merge.testbed = testbed
        candidate_default_none_op_merge.device = device
        candidate_default_none_op_merge.nxos = ncssh.SshConnect(host.host_ip(candidate_default_none_op_merge.testbed,candidate_default_none_op_merge.device))
        #config file from which config has to be sent as candidate config 
        config=netconf_config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        candidate_default_none_op_merge.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        candidate_default_none_op_merge.unconfig_file=config_file_dir+unconfig_file
        try :
            candidate_default_none_op_merge.message=nexus.nxos_xmlin(d,candidate_default_none_op_merge.device,candidate_default_none_op_merge.config,'edit-config')
            op_dict = {'3':'merge'}
            message=command.parse_req_op(candidate_default_none_op_merge.message,**op_dict)
            print message
            request= command.parse_req_default(message,"default-operation","none")
            print request
            candidate_default_none_op_merge.request = command.build_candidate(request)
            print candidate_default_none_op_merge.request
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def operation_test(self):
        self.obj = object()
        try :
            sessionid=candidate_default_none_op_merge.nxos.nc_sshconnect(username=host.username(candidate_default_none_op_merge.testbed,candidate_default_none_op_merge.device),password=host.password(candidate_default_none_op_merge.testbed,candidate_default_none_op_merge.device),command_timeout=120)
            logging.info ('session-id is %s' %(sessionid))
            response =candidate_default_none_op_merge.nxos._send(candidate_default_none_op_merge.request)

            #send candidate commit to switch
            request = command.build_candidate_commit()
            logging.info('sending candidate commit')
            response_2 = candidate_default_none_op_merge.nxos._send(request)
            logging.info('response is '+response_2)

            cmd_dict = {'3':'merge'}
            nexus.verify_op(d,candidate_default_none_op_merge.config,**cmd_dict)
            logging.info('configuration found on switch')
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
           
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = candidate_default_none_op_merge.nxos.closesession() 
        nexus.nxos_unconfig(d,candidate_default_none_op_merge.unconfig_file)
        int_value=Passed.code
        assert int_value == 1 

class candidate_operation_create(aetest.Testcase):

    logging.info ('This testcase tests operation as create for one command')

    @aetest.setup
    def setup(self,testbed,device,netconf_config_file,config_file_dir,unconfig_file):
        self.obj = object()
        candidate_operation_create.testbed = testbed
        candidate_operation_create.device = device
        candidate_operation_create.nxos = ncssh.SshConnect(host.host_ip(candidate_operation_create.testbed,candidate_operation_create.device))
        #config file from which config has to be sent as candidate config 
        config=netconf_config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        candidate_operation_create.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        candidate_operation_create.unconfig_file=config_file_dir+unconfig_file
        try :
            candidate_operation_create.message=nexus.nxos_xmlin(d,candidate_operation_create.device,candidate_operation_create.config,'edit-config')
            op_dict = {'1':'create'}
            request=command.parse_req_op(candidate_operation_create.message,**op_dict)
            candidate_operation_create.request = command.build_candidate(request)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def operation_test(self):
        self.obj = object()
        try :
            sessionid=candidate_operation_create.nxos.nc_sshconnect(username=host.username(candidate_operation_create.testbed,candidate_operation_create.device),password=host.password(candidate_operation_create.testbed,candidate_operation_create.device),command_timeout=120)
            logging.info ('session-id is %s' %(sessionid))
            response =candidate_operation_create.nxos._send(candidate_operation_create.request,0)
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
        finally:
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string,0)
            if error_list[1] == 'operation-not-supported' and error_list[3] == 'Operation not supported':
                int_value=Passed.code
                assert int_value == 1 
            else :
                int_value=Failed.code
                assert int_value == 1
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = candidate_operation_create.nxos.closesession() 
        nexus.nxos_unconfig(d,candidate_operation_create.unconfig_file)
        int_value=Passed.code
        assert int_value == 1 

class candidate_operation_delete(aetest.Testcase):

    logging.info ('This testcase tests operation as delete for one command')

    @aetest.setup
    def setup(self,testbed,device,netconf_config_file,config_file_dir,unconfig_file):
        self.obj = object()
        candidate_operation_delete.testbed = testbed
        candidate_operation_delete.device = device
        candidate_operation_delete.nxos = ncssh.SshConnect(host.host_ip(candidate_operation_delete.testbed,candidate_operation_delete.device))
        #config file from which config has to be sent as candidate config 
        config=netconf_config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        candidate_operation_delete.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        candidate_operation_delete.unconfig_file=config_file_dir+unconfig_file
        try :
            message=nexus.nxos_xmlin(d,candidate_operation_delete.device,candidate_operation_delete.config,'edit-config')
            candidate_operation_delete.request1 = command.build_candidate(message)
            op_dict = {'3':'delete','4':'delete','5':'delete'}
            message2=command.parse_req_op(candidate_operation_delete.request1,**op_dict)
            candidate_operation_delete.request2 = command.build_candidate(message2)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def operation_test(self):
        self.obj = object()
        try :
            sessionid=candidate_operation_delete.nxos.nc_sshconnect(username=host.username(candidate_operation_delete.testbed,candidate_operation_delete.device),password=host.password(candidate_operation_delete.testbed,candidate_operation_delete.device),command_timeout=120)
            logging.info ('session-id is %s' %(sessionid))
            response =candidate_operation_delete.nxos._send(candidate_operation_delete.request1)

            #now sending delete request on candidate
            response = candidate_operation_delete.nxos._send(candidate_operation_delete.request2)

            #sending candidate commit
            message = command.build_candidate_commit()
            logging.info ('sending candidate config commit to the switch')
            response =candidate_operation_delete.nxos._send(message,1)
            logging.info ('response is %s' % (response))

            #checking if candidate config is applied after sending commit 
            args = ['3']
            nexus.verify_error(d,candidate_operation_delete.config,'stop',*args)
            logging.info('candidate config is applied to switch after sending commit')
        
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = candidate_operation_delete.nxos.closesession() 
        nexus.nxos_unconfig(d,candidate_operation_delete.unconfig_file)
        int_value=Passed.code
        assert int_value == 1 

class empty_candidate_operation_delete(aetest.Testcase):

    logging.info ('This testcase tests operation as delete for one command without data in candidate datastore')

    @aetest.setup
    def setup(self,testbed,device,netconf_config_file,config_file_dir,unconfig_file):
        self.obj = object()
        empty_candidate_operation_delete.testbed = testbed
        empty_candidate_operation_delete.device = device
        empty_candidate_operation_delete.nxos = ncssh.SshConnect(host.host_ip(empty_candidate_operation_delete.testbed,empty_candidate_operation_delete.device))
        #config file from which config has to be sent as candidate config 
        config=netconf_config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        empty_candidate_operation_delete.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        empty_candidate_operation_delete.unconfig_file=config_file_dir+unconfig_file
        try :
            empty_candidate_operation_delete.message=nexus.nxos_xmlin(d,empty_candidate_operation_delete.device,empty_candidate_operation_delete.config,'edit-config')
            op_dict = {'3':'delete','4':'delete','5':'delete'}
            request=command.parse_req_op(empty_candidate_operation_delete.message,**op_dict)
            empty_candidate_operation_delete.request = command.build_candidate(request)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def operation_test(self):
        self.obj = object()
        try :
            sessionid=empty_candidate_operation_delete.nxos.nc_sshconnect(username=host.username(empty_candidate_operation_delete.testbed,empty_candidate_operation_delete.device),password=host.password(empty_candidate_operation_delete.testbed,empty_candidate_operation_delete.device),command_timeout=120)
            logging.info ('session-id is %s' %(sessionid))
            response =empty_candidate_operation_delete.nxos._send(empty_candidate_operation_delete.request,0)
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
        finally:
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string,0)
            if error_list[1] == 'data-missing' and error_list[3] == "Data doesn't exist":
                int_value=Passed.code
                assert int_value == 1 
            else :
                int_value=Failed.code
                assert int_value == 1            

    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = empty_candidate_operation_delete.nxos.closesession() 
        nexus.nxos_unconfig(d,empty_candidate_operation_delete.unconfig_file)
        int_value=Passed.code
        assert int_value == 1 

class confirmed_commit(aetest.Testcase):

    logging.info  ("This testcase tests the candidate option with confirmed-commit")
    
    @aetest.setup
    def setup(self,testbed,device,config_file_dir,config_file,unconfig_file):
        self.obj = object()
        confirmed_commit.testbed = testbed
        confirmed_commit.device = device
        confirmed_commit.nxos = ncssh.SshConnect(host.host_ip(confirmed_commit.testbed,confirmed_commit.device))
        #config file from which config has to be sent as candidate config 
        config=config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        confirmed_commit.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        confirmed_commit.unconfig_file=config_file_dir+unconfig_file
        try :
            message = nexus.nxos_xmlin(d,confirmed_commit.device,confirmed_commit.config,'edit-config')
            confirmed_commit.message = command.build_candidate(message)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def candidate_test(self):
        self.obj = object()
        try :
            sessionid=confirmed_commit.nxos.nc_sshconnect(username=host.username(confirmed_commit.testbed,confirmed_commit.device),password=host.password(confirmed_commit.testbed,confirmed_commit.device))
            logging.info ('session-id is %s' %(sessionid))
            logging.info ('sending candidate config request to the switch')

            #sending candidate config to the switch 
            response =confirmed_commit.nxos._send(confirmed_commit.message,1)
            logging.info ('response is %s' % (response))

            #check that candidate config is not applied to switch before sending commit 
            nexus.verify_default_op(d,confirmed_commit.config,'none')
            logging.info('candidate config is not yet applied to switch')

            #sending confirmed commit request
            message = command.build_confirmed_commit(30)
            logging.info ('sending confirmed commit to the switch with timeout as 30 seconds')
            response =confirmed_commit.nxos._send(message,1)
            logging.info ('response is %s' % (response))

            #checking if candidate config is applied after sending commit 
            nexus.verify_default_op(d,confirmed_commit.config,'merge')
            logging.info('candidate config is applied to switch after sending confirmed-commit')

            #sending candidate commit
            message = command.build_candidate_commit()
            logging.info ('sending candidate config commit to the switch')
            response =confirmed_commit.nxos._send(message,1)
            logging.info ('response is %s' % (response))

            time.sleep(60)
            #checking if candidate config is applied after sending commit 
            nexus.verify_default_op(d,confirmed_commit.config,'merge')
            logging.info('candidate config is applied to switch after sending commit')

            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('candidate Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            close_message = confirmed_commit.nxos.closesession()
            nexus.nxos_unconfig(d,confirmed_commit.unconfig_file)
            int_value=Passed.code
            assert int_value == 1  
        except nxos_XML_errors.NetConfRPCError :
            int_value=Failed.code
            assert int_value == 1

class confirmed_commit_timeout(aetest.Testcase):
    logging.info  ("This testcase tests the candidate option with confirmed-commit and not sending commit within timeout")

    
    @aetest.setup
    def setup(self,testbed,device,config_file_dir,config_file,unconfig_file):
        self.obj = object()
        confirmed_commit_timeout.testbed = testbed
        confirmed_commit_timeout.device = device
        confirmed_commit_timeout.nxos = ncssh.SshConnect(host.host_ip(confirmed_commit_timeout.testbed,confirmed_commit_timeout.device))
        #config file from which config has to be sent as candidate config 
        config=config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        confirmed_commit_timeout.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        confirmed_commit_timeout.unconfig_file=config_file_dir+unconfig_file
        try :
            message = nexus.nxos_xmlin(d,confirmed_commit_timeout.device,confirmed_commit_timeout.config,'edit-config')
            confirmed_commit_timeout.message = command.build_candidate(message)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def candidate_test(self):
        self.obj = object()
        try :
            sessionid=confirmed_commit_timeout.nxos.nc_sshconnect(username=host.username(confirmed_commit_timeout.testbed,confirmed_commit_timeout.device),password=host.password(confirmed_commit_timeout.testbed,confirmed_commit_timeout.device))
            logging.info ('session-id is %s' %(sessionid))
            logging.info ('sending candidate config request to the switch')

            #sending candidate config to the switch 
            response =confirmed_commit_timeout.nxos._send(confirmed_commit_timeout.message,1)
            logging.info ('response is %s' % (response))

            #check that candidate config is not applied to switch before sending commit 
            nexus.verify_default_op(d,confirmed_commit_timeout.config,'none')
            logging.info('candidate config is not yet applied to switch')

            #sending confirmed commit request
            message = command.build_confirmed_commit(30)
            logging.info ('sending confirmed commit to the switch with timeout as 30 seconds')
            response =confirmed_commit_timeout.nxos._send(message,1)
            logging.info ('response is %s' % (response))


            #checking if candidate config is applied after sending confirmed commit 
            nexus.verify_default_op(d,confirmed_commit_timeout.config,'merge')
            logging.info('candidate config is not applied to switch after confirmed commit is timedout')

            #sleeping for 30 secs to let confirmed commit timeout
            logging.info('sleeping for 60 sec to let confirmed commit timeout')
            time.sleep(60)

            #checking if candidate config is discarded after confirmed timeout 
            nexus.verify_default_op(d,confirmed_commit_timeout.config,'none')
            logging.info('candidate config is not applied to switch after confirmed commit is timedout')

            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('candidate Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            close_message = confirmed_commit_timeout.nxos.closesession()
            int_value=Passed.code
            assert int_value == 1  
        except nxos_XML_errors.NetConfRPCError :
            int_value=Failed.code
            assert int_value == 1

class confirmed_commit_2_consecutive_commits(aetest.Testcase):

    logging.info  ("This testcase tests the candidate option with sending two consecutive confirmed-commit requests")

    @aetest.setup
    def setup(self,testbed,device,config_file_dir,config_file,unconfig_file):
        self.obj = object()
        confirmed_commit_2_consecutive_commits.testbed = testbed
        confirmed_commit_2_consecutive_commits.device = device
        confirmed_commit_2_consecutive_commits.nxos = ncssh.SshConnect(host.host_ip(confirmed_commit_2_consecutive_commits.testbed,confirmed_commit_2_consecutive_commits.device))

        config=config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        confirmed_commit_2_consecutive_commits.config = command.cmd_req('edit-config',config_file)

        #unconfig file to be sent in the cleanup
        confirmed_commit_2_consecutive_commits.unconfig_file=config_file_dir+unconfig_file        
        
        try :
            message = nexus.nxos_xmlin(d,confirmed_commit_2_consecutive_commits.device,confirmed_commit_2_consecutive_commits.config,'edit-config')
            confirmed_commit_2_consecutive_commits.message = command.build_candidate(message)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def candidate_test(self):
        self.obj = object()
        try :
            sessionid=confirmed_commit_2_consecutive_commits.nxos.nc_sshconnect(username=host.username(confirmed_commit_2_consecutive_commits.testbed,confirmed_commit_2_consecutive_commits.device),password=host.password(confirmed_commit_2_consecutive_commits.testbed,confirmed_commit_2_consecutive_commits.device))
            logging.info ('session-id is %s' %(sessionid))
            logging.info ('sending candidate config request to the switch')

            #sending candidate config to the switch 
            response =confirmed_commit_2_consecutive_commits.nxos._send(confirmed_commit_2_consecutive_commits.message)
            logging.info ('response is %s' % (response))

            #sending confirmed commit request
            message = command.build_confirmed_commit(30)
            logging.info ('sending confirmed commit to the switch with timeout as 30 seconds')
            response =confirmed_commit_2_consecutive_commits.nxos._send(message)
            logging.info ('response is %s' % (response))

            #sending confirmed commit request
            message = command.build_confirmed_commit(30)
            logging.info ('sending confirmed commit to the switch with timeout as 30 seconds')
            response =confirmed_commit_2_consecutive_commits.nxos._send(message,0)
            logging.info ('response is %s' % (response))

        except nxos_XML_errors.NetConfRPCError:
            logging.error ('candidate Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string,0)
            if error_list[1] == "operation-not-supported" and error_list[3]== "Cannot do consecutive confirmed commit operation" :
                int_value=Passed.code
                assert int_value == 1 
            else :
                logging.error('incorrect error returned')
                int_value=Failed.code
                assert int_value == 1
     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            close_message = confirmed_commit_2_consecutive_commits.nxos.closesession()
            nexus.nxos_unconfig(d,confirmed_commit_2_consecutive_commits.unconfig_file)
            int_value=Passed.code
            assert int_value == 1  
        except nxos_XML_errors.NetConfRPCError :
            int_value=Failed.code
            assert int_value == 1

class edit_conf_url_as_source(aetest.Testcase):

    logging.info  ("This testcase tests the edit-config with url as source")
    
    @aetest.setup
    def setup(self,testbed,device,netconf_config_file,config_file_dir,unconfig_file):
        self.obj = object()
        edit_conf_url_as_source.testbed = testbed
        edit_conf_url_as_source.device = device
        edit_conf_url_as_source.nxos = ncssh.SshConnect(host.host_ip(edit_conf_url_as_source.testbed,edit_conf_url_as_source.device))
        
        #config file from which has to be sent as source in url 
        config_file=netconf_config_file

        config = config_file_dir+config_file

        #copying file from directory to bootflash of the device
        nexus.copy_file(edit_conf_url_as_source.testbed,d,config)

        edit_conf_url_as_source.config = command.cmd_req('edit-config',config)
        
        #unconfig file to be sent in the cleanup
        edit_conf_url_as_source.unconfig_file=config_file_dir+unconfig_file
        try :
            edit_conf_url_as_source.message = command.edit_config_url(d,edit_conf_url_as_source.device,config_file)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def edit_conf_url_as_source(self):
        self.obj = object()
        try :
            sessionid=edit_conf_url_as_source.nxos.nc_sshconnect(username=host.username(edit_conf_url_as_source.testbed,edit_conf_url_as_source.device),password=host.password(edit_conf_url_as_source.testbed,edit_conf_url_as_source.device))
            logging.info ('session-id is %s' %(sessionid))
            logging.info ('sending edit config with url request to the switch')

            #sending edit config to the switch 
            response =edit_conf_url_as_source.nxos._send(edit_conf_url_as_source.message,1)
            logging.info ('response is %s' % (response))

            nexus.verify_default_op(d,edit_conf_url_as_source.config,'merge')
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('edit config Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            close_message = edit_conf_url_as_source.nxos.closesession()
            nexus.nxos_unconfig(d,edit_conf_url_as_source.unconfig_file)
            int_value=Passed.code
            assert int_value == 1  
        except nxos_XML_errors.NetConfRPCError :
            int_value=Failed.code
            assert int_value == 1


class edit_conf_url_as_source_default_operation_none(aetest.Testcase):

    logging.info  ("This testcase tests the edit-config with url as source with default operation as none")
    
    @aetest.setup
    def setup(self,testbed,device,netconf_config_file,config_file_dir,unconfig_file):
        self.obj = object()
        edit_conf_url_as_source_default_operation_none.testbed = testbed
        edit_conf_url_as_source_default_operation_none.device = device
        edit_conf_url_as_source_default_operation_none.nxos = ncssh.SshConnect(host.host_ip(edit_conf_url_as_source_default_operation_none.testbed,edit_conf_url_as_source_default_operation_none.device))
        
        #config file from which has to be sent as source in url 
        config_file=netconf_config_file

        config = config_file_dir+config_file

        #copying file from directory to bootflash of the device
        nexus.copy_file(edit_conf_url_as_source_default_operation_none.testbed,d,config)

        edit_conf_url_as_source_default_operation_none.config = command.cmd_req('edit-config',config)
        #unconfig file to be sent in the cleanup
        edit_conf_url_as_source_default_operation_none.unconfig_file=config_file_dir+unconfig_file
        try :
            edit_conf_url_as_source_default_operation_none.message = command.edit_config_url(d,edit_conf_url_as_source_default_operation_none.device,config_file,operation='none')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def edit_conf_url_as_source_default_operation_none(self):
        self.obj = object()
        try :
            sessionid=edit_conf_url_as_source_default_operation_none.nxos.nc_sshconnect(username=host.username(edit_conf_url_as_source_default_operation_none.testbed,edit_conf_url_as_source_default_operation_none.device),password=host.password(edit_conf_url_as_source_default_operation_none.testbed,edit_conf_url_as_source_default_operation_none.device))
            logging.info ('session-id is %s' %(sessionid))
            logging.info ('sending edit config with url request to the switch')

            #sending edit config to the switch 
            response =edit_conf_url_as_source_default_operation_none.nxos._send(edit_conf_url_as_source_default_operation_none.message,1)
            logging.info ('response is %s' % (response))

            nexus.verify_default_op(d,edit_conf_url_as_source_default_operation_none.config,'none')
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('edit config Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            close_message = edit_conf_url_as_source_default_operation_none.nxos.closesession()
            nexus.nxos_unconfig(d,edit_conf_url_as_source_default_operation_none.unconfig_file)
            int_value=Passed.code
            assert int_value == 1  
        except nxos_XML_errors.NetConfRPCError :
            int_value=Failed.code
            assert int_value == 1

class edit_conf_url_as_source_default_operation_merge(aetest.Testcase):

    logging.info  ("This testcase tests the edit-config with url as source with default operation as merge")
    
    @aetest.setup
    def setup(self,testbed,device,netconf_config_file,config_file_dir,unconfig_file):
        self.obj = object()
        edit_conf_url_as_source_default_operation_merge.testbed = testbed
        edit_conf_url_as_source_default_operation_merge.device = device
        edit_conf_url_as_source_default_operation_merge.nxos = ncssh.SshConnect(host.host_ip(edit_conf_url_as_source_default_operation_merge.testbed,edit_conf_url_as_source_default_operation_merge.device))
        
        #config file from which has to be sent as source in url 
        config_file=netconf_config_file

        config = config_file_dir+config_file

        #copying file from directory to bootflash of the device
        nexus.copy_file(edit_conf_url_as_source_default_operation_merge.testbed,d,config)

        edit_conf_url_as_source_default_operation_merge.config = command.cmd_req('edit-config',config)
        #unconfig file to be sent in the cleanup
        edit_conf_url_as_source_default_operation_merge.unconfig_file=config_file_dir+unconfig_file
        try :
            edit_conf_url_as_source_default_operation_merge.message = command.edit_config_url(d,edit_conf_url_as_source_default_operation_merge.device,config_file,operation='merge')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def edit_conf_url_as_source_default_operation_merge(self):
        self.obj = object()
        try :
            sessionid=edit_conf_url_as_source_default_operation_merge.nxos.nc_sshconnect(username=host.username(edit_conf_url_as_source_default_operation_merge.testbed,edit_conf_url_as_source_default_operation_merge.device),password=host.password(edit_conf_url_as_source_default_operation_merge.testbed,edit_conf_url_as_source_default_operation_merge.device))
            logging.info ('session-id is %s' %(sessionid))
            logging.info ('sending edit config with url request to the switch')

            #sending edit config to the switch 
            response =edit_conf_url_as_source_default_operation_merge.nxos._send(edit_conf_url_as_source_default_operation_merge.message,1)
            logging.info ('response is %s' % (response))

            nexus.verify_default_op(d,edit_conf_url_as_source_default_operation_merge.config,'merge')
            logging.info('config is configured on the switch')
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('edit config Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            close_message = edit_conf_url_as_source_default_operation_merge.nxos.closesession()
            nexus.nxos_unconfig(d,edit_conf_url_as_source_default_operation_merge.unconfig_file)
            int_value=Passed.code
            assert int_value == 1  
        except nxos_XML_errors.NetConfRPCError :
            int_value=Failed.code
            assert int_value == 1

class edit_conf_url_set(aetest.Testcase):

    logging.info  ("This testcase tests the edit-config with url as source with test-option as set")
    
    @aetest.setup
    def setup(self,testbed,device,netconf_error_file,config_file_dir,unconfig_file):
        self.obj = object()
        edit_conf_url_set.testbed = testbed
        edit_conf_url_set.device = device
        edit_conf_url_set.nxos = ncssh.SshConnect(host.host_ip(edit_conf_url_set.testbed,edit_conf_url_set.device))
        
        #config file from which has to be sent as source in url 
        config_file=netconf_error_file

        config = config_file_dir+config_file

        #copying file from directory to bootflash of the device
        nexus.copy_file(edit_conf_url_set.testbed,d,config)

        edit_conf_url_set.config = command.cmd_req('edit-config',config)
        #unconfig file to be sent in the cleanup
        edit_conf_url_set.unconfig_file=config_file_dir+unconfig_file
        try :
            edit_conf_url_set.message = command.edit_config_url(d,edit_conf_url_set.device,config_file,test_option='set')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def edit_conf_url_set(self):
        self.obj = object()
        try :
            sessionid=edit_conf_url_set.nxos.nc_sshconnect(username=host.username(edit_conf_url_set.testbed,edit_conf_url_set.device),password=host.password(edit_conf_url_set.testbed,edit_conf_url_set.device))
            logging.info ('session-id is %s' %(sessionid))
            logging.info ('sending edit config with url request to the switch')

            #sending edit config to the switch 
            response =edit_conf_url_set.nxos._send(edit_conf_url_set.message,0)
            logging.info ('response is %s' % (response))
            args = ['3']
            nexus.verify_error(d,edit_conf_url_set.config,'stop',*args)
            logging.info('config is configured on the switch')
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('edit config Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string,0)
            if error_list[1]=='invalid-value' and 'Syntax error while parsing' in error_list[3]:
                logging.info ('invalid value sent')
                logging.info ('error is %s' %error_list[3])
                int_value=Passed.code   
                assert int_value == 1 
            else :
                logging.debug ('Incorrect error returned')
                int_value=Failed.code
                assert int_value == 1 
     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            close_message = edit_conf_url_set.nxos.closesession()
            nexus.nxos_unconfig(d,edit_conf_url_set.unconfig_file)
            int_value=Passed.code
            assert int_value == 1  
        except nxos_XML_errors.NetConfRPCError :
            int_value=Failed.code
            assert int_value == 1

class edit_conf_url_test_then_set(aetest.Testcase):

    logging.info  ("This testcase tests the edit-config with url as source with test-option as test-then-set")
    
    @aetest.setup
    def setup(self,testbed,device,netconf_error_file,config_file_dir,unconfig_file):
        self.obj = object()
        edit_conf_url_test_then_set.testbed = testbed
        edit_conf_url_test_then_set.device = device
        edit_conf_url_test_then_set.nxos = ncssh.SshConnect(host.host_ip(edit_conf_url_test_then_set.testbed,edit_conf_url_test_then_set.device))
        
        #config file from which has to be sent as source in url 
        config_file=netconf_error_file

        config = config_file_dir+config_file

        #copying file from directory to bootflash of the device
        nexus.copy_file(edit_conf_url_test_then_set.testbed,d,config)

        edit_conf_url_test_then_set.config = command.cmd_req('edit-config',config)
        #unconfig file to be sent in the cleanup
        edit_conf_url_test_then_set.unconfig_file=config_file_dir+unconfig_file
        try :
            edit_conf_url_test_then_set.message = command.edit_config_url(d,edit_conf_url_test_then_set.device,config_file,test_option='test-then-set')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def edit_conf_url_test_then_set(self):
        self.obj = object()
        try :
            sessionid=edit_conf_url_test_then_set.nxos.nc_sshconnect(username=host.username(edit_conf_url_test_then_set.testbed,edit_conf_url_test_then_set.device),password=host.password(edit_conf_url_test_then_set.testbed,edit_conf_url_test_then_set.device))
            logging.info ('session-id is %s' %(sessionid))
            logging.info ('sending edit config with url request to the switch')

            #sending edit config to the switch 
            response =edit_conf_url_test_then_set.nxos._send(edit_conf_url_test_then_set.message,0)
            logging.info ('response is %s' % (response))
            args = ['3']
            nexus.verify_error(d,edit_conf_url_test_then_set.config,'rollback',*args)
            logging.info('config is configured on the switch')
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('edit config Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string,0)
            if error_list[1]=='invalid-value' and 'Syntax error while parsing' in error_list[3]:
                logging.info ('invalid value sent')
                logging.info ('error is %s' %error_list[3])
                int_value=Passed.code   
                assert int_value == 1 
            else :
                logging.debug ('Incorrect error returned')
                int_value=Failed.code
                assert int_value == 1 
     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            close_message = edit_conf_url_test_then_set.nxos.closesession()
            nexus.nxos_unconfig(d,edit_conf_url_test_then_set.unconfig_file)
            int_value=Passed.code
            assert int_value == 1  
        except nxos_XML_errors.NetConfRPCError :
            int_value=Failed.code
            assert int_value == 1

class edit_conf_url_continue_on_error(aetest.Testcase):

    logging.info  ("This testcase tests the edit-config with url as source with error-option as continue-on-error")
    
    @aetest.setup
    def setup(self,testbed,device,netconf_error_file,config_file_dir,unconfig_file):
        self.obj = object()
        edit_conf_url_continue_on_error.testbed = testbed
        edit_conf_url_continue_on_error.device = device
        edit_conf_url_continue_on_error.nxos = ncssh.SshConnect(host.host_ip(edit_conf_url_continue_on_error.testbed,edit_conf_url_continue_on_error.device))
        
        #config file from which has to be sent as source in url 
        config_file=netconf_error_file

        config = config_file_dir+config_file

        #copying file from directory to bootflash of the device
        nexus.copy_file(edit_conf_url_continue_on_error.testbed,d,config)

        edit_conf_url_continue_on_error.config = command.cmd_req('edit-config',config)
        #unconfig file to be sent in the cleanup
        edit_conf_url_continue_on_error.unconfig_file=config_file_dir+unconfig_file
        try :
            edit_conf_url_continue_on_error.message = command.edit_config_url(d,edit_conf_url_continue_on_error.device,config_file,error_option='continue-on-error')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def edit_conf_url_continue_on_error(self):
        self.obj = object()
        try :
            sessionid=edit_conf_url_continue_on_error.nxos.nc_sshconnect(username=host.username(edit_conf_url_continue_on_error.testbed,edit_conf_url_continue_on_error.device),password=host.password(edit_conf_url_continue_on_error.testbed,edit_conf_url_continue_on_error.device))
            logging.info ('session-id is %s' %(sessionid))
            logging.info ('sending edit config with url request to the switch')

            #sending edit config to the switch 
            response =edit_conf_url_continue_on_error.nxos._send(edit_conf_url_continue_on_error.message,0)
            logging.info ('response is %s' % (response))

            args = ['3']
            nexus.verify_error(d,edit_conf_url_continue_on_error.config,'continue',*args)
            logging.info('config is configured on the switch') 
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('edit config Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string,0)
            if error_list[1]=='invalid-value' and 'Syntax error while parsing' in error_list[3]:
                logging.info ('invalid value sent')
                logging.info ('error is %s' %error_list[3])
                int_value=Passed.code   
                assert int_value == 1 
            else :
                logging.debug ('Incorrect error returned')
                int_value=Failed.code
                assert int_value == 1 
     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            close_message = edit_conf_url_continue_on_error.nxos.closesession()
            nexus.nxos_unconfig(d,edit_conf_url_continue_on_error.unconfig_file)
            int_value=Passed.code
            assert int_value == 1  
        except nxos_XML_errors.NetConfRPCError :
            int_value=Failed.code
            assert int_value == 1

class edit_conf_url_stop_on_error(aetest.Testcase):

    logging.info  ("This testcase tests the edit-config with url as source with error-option as stop-on-error")
    
    @aetest.setup
    def setup(self,testbed,device,netconf_error_file,config_file_dir,unconfig_file):
        self.obj = object()
        edit_conf_url_stop_on_error.testbed = testbed
        edit_conf_url_stop_on_error.device = device
        edit_conf_url_stop_on_error.nxos = ncssh.SshConnect(host.host_ip(edit_conf_url_stop_on_error.testbed,edit_conf_url_stop_on_error.device))
        
        #config file from which has to be sent as source in url 
        config_file=netconf_error_file

        config = config_file_dir+config_file

        #copying file from directory to bootflash of the device
        nexus.copy_file(edit_conf_url_stop_on_error.testbed,d,config)

        edit_conf_url_stop_on_error.config = command.cmd_req('edit-config',config)
        #unconfig file to be sent in the cleanup
        edit_conf_url_stop_on_error.unconfig_file=config_file_dir+unconfig_file
        try :
            edit_conf_url_stop_on_error.message = command.edit_config_url(d,edit_conf_url_stop_on_error.device,config_file,error_option='stop-on-error')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def edit_conf_url_stop_on_error(self):
        self.obj = object()
        try :
            sessionid=edit_conf_url_stop_on_error.nxos.nc_sshconnect(username=host.username(edit_conf_url_stop_on_error.testbed,edit_conf_url_stop_on_error.device),password=host.password(edit_conf_url_stop_on_error.testbed,edit_conf_url_stop_on_error.device))
            logging.info ('session-id is %s' %(sessionid))
            logging.info ('sending edit config with url request to the switch')

            #sending edit config to the switch 
            response =edit_conf_url_stop_on_error.nxos._send(edit_conf_url_stop_on_error.message,0)
            logging.info ('response is %s' % (response))

            args = ['3']
            nexus.verify_error(d,edit_conf_url_stop_on_error.config,'stop',*args)
            logging.info('config is configured on the switch')

        except nxos_XML_errors.NetConfRPCError:
            logging.error ('edit config Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string,0)
            if error_list[1]=='invalid-value' and 'Syntax error while parsing' in error_list[3]:
                logging.info ('invalid value sent')
                logging.info ('error is %s' %error_list[3])
                int_value=Passed.code   
                assert int_value == 1 
            else :
                logging.debug ('Incorrect error returned')
                int_value=Failed.code
                assert int_value == 1 
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            close_message = edit_conf_url_stop_on_error.nxos.closesession()
            nexus.nxos_unconfig(d,edit_conf_url_stop_on_error.unconfig_file)
            int_value=Passed.code
            assert int_value == 1  
        except nxos_XML_errors.NetConfRPCError :
            int_value=Failed.code
            assert int_value == 1

class edit_conf_url_rollback_on_error(aetest.Testcase):

    logging.info  ("This testcase tests the edit-config with url as source with error-option as rollback-on-error")
    
    @aetest.setup
    def setup(self,testbed,device,netconf_error_file,config_file_dir,unconfig_file):
        self.obj = object()
        edit_conf_url_rollback_on_error.testbed = testbed
        edit_conf_url_rollback_on_error.device = device
        edit_conf_url_rollback_on_error.nxos = ncssh.SshConnect(host.host_ip(edit_conf_url_rollback_on_error.testbed,edit_conf_url_rollback_on_error.device))
        
        #config file from which has to be sent as source in url 
        config_file=netconf_error_file

        config = config_file_dir+config_file

        #copying file from directory to bootflash of the device
        nexus.copy_file(edit_conf_url_rollback_on_error.testbed,d,config)

        edit_conf_url_rollback_on_error.config = command.cmd_req('edit-config',config)
        #unconfig file to be sent in the cleanup
        edit_conf_url_rollback_on_error.unconfig_file=config_file_dir+unconfig_file
        try :
            edit_conf_url_rollback_on_error.message = command.edit_config_url(d,edit_conf_url_rollback_on_error.device,config_file,error_option='rollback-on-error')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def edit_conf_url_rollback_on_error(self):
        self.obj = object()
        try :
            sessionid=edit_conf_url_rollback_on_error.nxos.nc_sshconnect(username=host.username(edit_conf_url_rollback_on_error.testbed,edit_conf_url_rollback_on_error.device),password=host.password(edit_conf_url_rollback_on_error.testbed,edit_conf_url_rollback_on_error.device))
            logging.info ('session-id is %s' %(sessionid))
            logging.info ('sending edit config with url request to the switch')

            #sending edit config to the switch 
            response =edit_conf_url_rollback_on_error.nxos._send(edit_conf_url_rollback_on_error.message,0)
            logging.info ('response is %s' % (response))

            args = ['3']
            nexus.verify_error(d,edit_conf_url_rollback_on_error.config,'rollback',*args)
            logging.info('config is configured on the switch') 
        except nxos_XML_errors.NetConfRPCError:
            logging.error ('edit config Failed due to RPC-error')
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
        finally :
            error_string = ncssh._stripdelim(response)
            error_list=ncssh.rpc_error(error_string,0)
            if error_list[1]=='invalid-value' and 'Syntax error while parsing' in error_list[3]:
                logging.info ('invalid value sent')
                logging.info ('error is %s' %error_list[3])
                int_value=Passed.code   
                assert int_value == 1 
            else :
                logging.debug ('Incorrect error returned')
                int_value=Failed.code
                assert int_value == 1 
     
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        try :
            close_message = edit_conf_url_rollback_on_error.nxos.closesession()
            nexus.nxos_unconfig(d,edit_conf_url_rollback_on_error.unconfig_file)
            int_value=Passed.code
            assert int_value == 1  
        except nxos_XML_errors.NetConfRPCError :
            int_value=Failed.code
            assert int_value == 1

@aetest.loop(config=get_edit_config_list)
class edit_config(aetest.Testcase):

    @aetest.setup
    def setup(self,testbed,device,config,edit_config_location):
        self.obj = object()
        edit_config.testbed = testbed
        edit_config.device = device
        edit_config.nxos = ncssh.SshConnect(host.host_ip(edit_config.testbed,edit_config.device))
        config_file= edit_config_location+config
        logging.info ('this testcase tests edit_config for file %s' %config_file)
        config = command.cmd_req('edit-config',config_file)
        try :
            edit_config.message=nexus.nxos_xmlin(d,edit_config.device,config,'edit-config')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def edit_config(self):
        self.obj = object()
        try :
            sessionid=edit_config.nxos.nc_sshconnect(username=host.username(edit_config.testbed,edit_config.device),password=host.password(edit_config.testbed,edit_config.device),command_timeout=120)
            logging.info ('session with id %s established' %(sessionid))
            response =edit_config.nxos._send(edit_config.message,1)
            logging.info ('response is %s' % (response))
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
            
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = edit_config.nxos.closesession() 
        int_value=Passed.code
        assert int_value == 1 

@aetest.loop(show=get_show_cmd_list)
class get(aetest.Testcase):

    @aetest.setup
    def setup(self,testbed,device,show,show_cmd_location):
        self.obj = object()
        get.testbed = testbed
        get.device = device
        get.nxos = ncssh.SshConnect(host.host_ip(get.testbed,get.device))
        show_file = show_cmd_location+show
        logging.info('this testcase tests rpc get for file %s' %show_file)
        show = command.cmd_req('get',show_file)
        try :
            get.message=nexus.nxos_xmlin(d,get.device,show,'get')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def get_test(self):
        self.obj = object()
        try :
            sessionid=get.nxos.nc_sshconnect(username=host.username(get.testbed,get.device),password=host.password(get.testbed,get.device),command_timeout=120)
            logging.info ('session with id %s established' %(sessionid))
            response =get.nxos._send(get.message)
            logging.info ('response is %s' % (response))
            command.verify_show(response)
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.ShowError:
            int_value=Failed.code
            assert int_value == 1
            
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = get.nxos.closesession() 
        int_value=Passed.code
        assert int_value == 1

class get_config_running_config(aetest.Testcase):

    logging.info('this testcase test get-config for running config')

    @aetest.setup
    def setup(self,testbed,device):
        self.obj = object()
        get_config_running_config.testbed = testbed
        get_config_running_config.device = device
        get_config_running_config.nxos = ncssh.SshConnect(host.host_ip(get_config_running_config.testbed,get_config_running_config.device))
        get_config_running_config.cmd = 'show running-config'
        try :
            get_config_running_config.message=nexus.nxos_xmlin(d,get_config_running_config.device,get_config_running_config.cmd,'get')
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def get_test(self):
        self.obj = object()
        try :
            sessionid=get_config_running_config.nxos.nc_sshconnect(username=host.username(get_config_running_config.testbed,get_config_running_config.device),password=host.password(get_config_running_config.testbed,get_config_running_config.device),command_timeout=120)
            logging.info ('session with id %s established' %(sessionid))
            response =get_config_running_config.nxos._send(get_config_running_config.message)
            logging.info ('response is %s' % (response))
            
            #verifying if output from cli and netconf is same 
            command.verify_get_config(d,get_config_running_config.cmd,response)
            logging.info ('the cli and netconf output for the command %s matches' %get_config_running_config.cmd)
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.GetConfigError:
            logging.error('This testcase Failed due to Getconfig error')
            int_value=Failed.code
            assert int_value == 1
            
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = get_config_running_config.nxos.closesession() 
        int_value=Passed.code
        assert int_value == 1

class get_config_running_config_with_candidate_config(aetest.Testcase):

    logging.info('this testcase test get-config for running config with candidate config')

    @aetest.setup
    def setup(self,testbed,device,config_file,config_file_dir):
        self.obj = object()
        get_config_running_config_with_candidate_config.testbed = testbed
        get_config_running_config_with_candidate_config.device = device
        get_config_running_config_with_candidate_config.nxos = ncssh.SshConnect(host.host_ip(get_config_running_config_with_candidate_config.testbed,get_config_running_config_with_candidate_config.device))
        get_config_running_config_with_candidate_config.cmd = 'show running-config'

        config=config_file

        config_file = config_file_dir+config

        #getting the configuration from the config file
        get_config_running_config_with_candidate_config.config = command.cmd_req('edit-config',config_file)

        try :
            message = nexus.nxos_xmlin(d,get_config_running_config_with_candidate_config.device,get_config_running_config_with_candidate_config.config,'edit-config')
            get_config_running_config_with_candidate_config.message_1 = command.build_candidate(message)
            get_config_running_config_with_candidate_config.message_2 = command.get_config_candidate(d,get_config_running_config_with_candidate_config.device)
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def get_test(self):
        self.obj = object()
        try :
            sessionid=get_config_running_config_with_candidate_config.nxos.nc_sshconnect(username=host.username(get_config_running_config_with_candidate_config.testbed,get_config_running_config_with_candidate_config.device),password=host.password(get_config_running_config_with_candidate_config.testbed,get_config_running_config_with_candidate_config.device),command_timeout=120)
            logging.info ('session with id %s established' %(sessionid))
            logging.info ('sending candidate config')
            response =get_config_running_config_with_candidate_config.nxos._send(get_config_running_config_with_candidate_config.message_1)
            logging.info ('response is %s' % (response))
            
            #check that candidate config is not applied to switch before sending commit 
            nexus.verify_default_op(d,get_config_running_config_with_candidate_config.config,'none')
            logging.info('candidate config is not yet applied to running-config')
            
            logging.info ('sending get-config request')
            response =get_config_running_config_with_candidate_config.nxos._send(get_config_running_config_with_candidate_config.message_2)
            logging.info ('response is %s' % (response))

            #verifying if output from cli and netconf is same 
            command.verify_get_config(d,get_config_running_config_with_candidate_config.cmd,response,candidate=1,candidate_commands=get_config_running_config_with_candidate_config.config)
            logging.info ('the output from cli and netconf matches for command %s with candidate config' %get_config_running_config_with_candidate_config.cmd)
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.GetConfigError:
            logging.error('This testcase Failed due to Getconfig error')
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.RunConfigError :
            int_value=Failed.code
            assert int_value == 1
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = get_config_running_config_with_candidate_config.nxos.closesession() 
        int_value=Passed.code
        assert int_value == 1

class batch(aetest.Testcase):

    logger.info('This testcase tests batch processing of get request')
    @aetest.setup
    def setup(self,testbed,device,config_file_dir,batch_file):
        self.obj = object()
        batch.testbed = testbed
        batch.device = device
        batch.nxos = ncssh.SshConnect(host.host_ip(batch.testbed,batch.device))
        cmd_list =  command.cmd_req('get',config_file_dir+batch_file)
        batch.match_count = len(cmd_list.split('\n'))
        batch.request = command.create_batch_request(d,batch.device,cmd_list)
        logging.info ('request to be sent is %s' %batch.request)
        try :
            int_value = Passed.code
            assert int_value == 1
        except :
            int_value = Failed.code
            assert int_value == 1

    @aetest.test
    def get_test(self):
        self.obj = object()
        try :
            sessionid=batch.nxos.nc_sshconnect(username=host.username(batch.testbed,batch.device),password=host.password(batch.testbed,batch.device),command_timeout=60)
            logging.info ('session with id %s established' %(sessionid))
            logging.info ('sending batch request to the switch')
            response = batch.nxos._send(batch.request,0,6,batch.match_count)
            logging.info ('response is %s' %response)

            #check if the received response is valid or not
            command.check_batch_process_response(response)
            int_value=Passed.code
            assert int_value == 1 
        except nxos_XML_errors.NetConfRPCError:
            int_value=Failed.code
            assert int_value == 1
        except nxos_XML_errors.ShowError:
            logging.error('invalid response received')
            int_value=Failed.code
            assert int_value == 1
            
    @aetest.cleanup
    def cleanup(self):
        self.obj = object()
        close_message = batch.nxos.closesession() 
        int_value=Passed.code
        assert int_value == 1 

class common_cleanup(aetest.CommonCleanup):

	logger.info('this is common cleanup')		
	@aetest.subsection
	def disconnect(self):
		try :
			d.disconnect()
			int_value = Passed.code
			assert int_value == 1
		except :
			int_value = Failed.code
			assert int_value == 1
