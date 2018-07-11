import abc
import functools
import thread
import os
import socket
import getpass
import sys
import traceback
import host
import time
import re
import nxos_XML_errors
import xml.etree.ElementTree as ET

# For later multi-thread support
import threading

import paramiko

import logging

#from nxos_XML_errors import TimeoutExpiredError, ServerClosedChannelError, NotConnectedError

# Static Variables, global for now

DEBUG = False
KEYFILE = "paramikolocalhostkeys"
LOGFILE = "netconflog.log"
MSG_DELIM=']]>]]>'


logger = logging.getLogger(__name__)
LOGLEVEL = logging.INFO
logger.setLevel(LOGLEVEL)

logger.info("Starting SSH")


# For adding threading at a later date
stdoutmutex = threading.Lock()
conmutex = threading.Lock()


def checkconnection(func):
    @functools.wraps(func)
    def decorator(self, *args, **kwargs):
        self.logger.debug('checkconnection: instance %s of class %s is now decorated with checkconnection, whee!' % (
            self, self.__class__))
        if not self.sshconnected:
            self.logger.error(
                "checkconnection: The ssh connection to {} is currently closed. Please reconnect and try again.".format(
                    self.host))
            raise nxos_XML_errors.NotConnectedError(
                "The ssh connection to {} is currently closed. Please reconnect and try again.".format(self.host))
        else:
            try:
                result = func(self, *args, **kwargs)
            except:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                stacktrace = traceback.extract_tb(exc_traceback)
                self.logger.debug("checkconnection: Error with the SSH message")
                self.logger.debug(sys.exc_info())
                self.logger.debug(stacktrace)
                raise
            else:
                return result

    return decorator

def _stripdelim(xmlstring):
    """
    str <- str
    Strip out the netconf message delim because it confuses the xml parsrer

    Takes an xml string and returns the same string without the netconf delimeter
    @param xmlstring:
    """

    return xmlstring[:xmlstring.find(MSG_DELIM)]


def rpcparse(rpcreply, rpcmessageid=None):
    """
    Parses the rpc reply message received from server
    Stolen from ncclient

    @type rpcreply: str
    @param rpcreply: string containing the rpc reply message
    """
    BASE_NS_1_0 = "urn:ietf:params:xml:ns:netconf:base:1.0"
    
    if rpcreply:
        root = ET.fromstring(rpcreply)
        if rpcmessageid:
            attribs = root.attrib
            if 'message-id' in attribs and attribs['message-id'] != rpcmessageid:
                raise NetConfRPCError("RPC Error from Server: Wrong message-id in reply {0}".format(rpcreply))
                # Per RFC 4741 an <ok/> tag is sent when there are no errors or warnings or data
        ok = root.find("{{{0}}}ok".format(BASE_NS_1_0))
        if ok is None:
            _rpc_error_parser(root)

def _rpc_error_parser(root):
    """
    Parses
    @param root: lxml object
    @return: raises exception if RPC error detected
    """
    BASE_NS_1_0 = "urn:ietf:params:xml:ns:netconf:base:1.0"
    error = root.findall("{{{0}}}rpc-error".format(BASE_NS_1_0))
    if error:
        for e in error:
            for t in e.itertext():
                if t == 'current session timed out':
                    raise nxos_XML_errors.NotConnectedError(
                    "Server indicates that the current session has timed out: {}".format(ET.tostring(root)))
        raise nxos_XML_errors.NetConfRPCError("RPC Error from Server: {0}".format(ET.tostring(root)))

def rpc_error(error_msg,error_ele=1) :

    error_response = error_msg
    #parses the error tags in the error reply and returns them as a list
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
    
    if error_ele == 1 :
        error_element = root[0][4][0].text
        error_list.append(error_element)
    
        logger.debug ("error_type is %s , error_tag is %s , error_severity is %s , error_message is %s and error_element is %s" %(error_type , error_tag , error_severity, error_message, error_element))
    else :
        logger.debug ("error_type is %s , error_tag is %s , error_severity is %s , error_message is %s" %(error_type , error_tag , error_severity, error_message))
        
    return (error_list)

    
class SshConnect(object):
    """
    Sets Up SSH v2 Session 
    """

    #----------------------------------------------------------------------
    def __init__(self, host):

        """
        Initialize ssh object
        *host* is the hostname or IP address to connect to
        @param host: str

        """

        self.logger = logging.getLogger('ncssh.SshConnect')

        self.host = host

        self.logger.debug("Creating SSH Cliet Object for " + self.host)

        self._transport = None
        self._sshconnected = False

        self.known_hosts = None
        
        self.server_capabilities = None
        self.sessionid = None
        self._ncconnected = False
        self._rpcmessageid = None
        self._useprovidedmessageid = False


    def sshconnect(self, port=22, timeout=None, unknown_host_cb='autoaddpolicy',
                   username=None, password=None, host_key_filename=None, key_filename=None, allow_agent=True,
                   look_for_keys=False, command_timeout=30, **kwargs):
        """
        Connect via SSH and initialize a session. First attempts the publickey
        authentication method and then password authentication.

        To disable attempting publickey authentication altogether, call with
         *allow_agent* and *look_for_keys* as `False`.

        Must be called with the following options:

        -    *port* is by default 22

        -    *timeout* is an optional timeout for socket connect

        -    *unknown_host_cb* is called when the server host key is not recognized. It takes two arguments, the hostname and the fingerprint (see the signature of :func:`default_unknown_host_cb`)

        -    *username* is the username to use for SSH authentication

        -    *password* is the password used if using password authentication, or the passphrase to use for unlocking keys that require it

        -    *host_key_filename* is a filename where the host keys are located. If *filename* is not specified, looks in the default locations i.e. :file:`~/.ssh/known_hosts` and :file:`~/ssh/known_hosts` for Windows

        -    *key_filename* is a filename where a the private key to be used can be found

        -    *allow_agent* enables querying SSH agent (if found) for keys

        -    *look_for_keys* enables looking in the usual locations for ssh keys (e.g. :file:`~/.ssh/id_*`)

        -    *command_timeout* time in seconds to wait for expected output from server, default is 30 seconds


        -    @type port: int
        -    @type timeout: float
        -    @type username: str
        -    @type password: str
        -    @type unknown_host_cb: str
        -    @type host_key_filename: str
        -    @type key_filename: str
        -    @type allow_agent: bool
        -    @type look_for_keys: bool
        -    @type command_timeout: float

        This method relies on the self.setup_channel method for defining the channel characteristics
        This is defined as an abstract method
        Since there are multiple channel options, it is up to the subclass to define this method, probably using the ssh_subsystem method or the ssh_shell method

        For example the subclass could define the method as

        ::

            def setup_channel():
                self.ssh_subsystem('xmlagent')

        """

        self.port = port
        self.timeout = timeout
        self.username = username
        self.password = password
        self.unknown_host_cb = unknown_host_cb
        self.host_key_filename = host_key_filename
        self.key_filename = key_filename
        self.allow_agent = allow_agent
        self.look_for_keys = look_for_keys
        self._command_timeout = command_timeout
        self.ssh_client = None
        self._transport = None
        self._sshconnected = False
        self._channel = None

        if self.username is None:
            self.username = getpass.getuser()
        if self.password is None:
            self.password = getpass.getpass("Enter password for " + self.username + " :  ")

        self.logger.debug("Creating SSH connection to " + self.host)

        self.ssh_object()
        self.logger.debug("SSH object instantiated")
        self.ssh_client.set_log_channel(self.logger.name)
        self.ssh_connect()
        self.logger.debug("Connected to host " + self.host)
        self.logger.debug("Setting up channel to {}".format(self.host))

        #The setup_channel method is abstract and Must be defined by a subclass
        self.setup_channel()
        if self._transport.is_active() and self._transport.is_authenticated():
            self._sshconnected = True

        socket.setdefaulttimeout(self.command_timeout + 60.0)


    def ssh_object(self):
        """
        Instantiates Paramiko SSH Cliet object and Configures Host Key Policy
        """
        try:
            self.logger.debug("Instantiating Paramiko SSH Client Object for connecting to " + self.host)
            self.ssh_client = paramiko.SSHClient()
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.critical("Error creating SSH object for host " + self.host)
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            raise
        if self.unknown_host_cb == 'autoaddpolicy':
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            self.logger.critical("Unsupported Unknown Host Policy for " + self.host)
            raise NotImplementedError
        if self.host_key_filename is None:
            filename = os.path.expanduser('~/.ssh/known_hosts')
            self.logger.debug("Looking for system known_hosts keys file for " + self.host)
            try:
                self.ssh_client.load_host_keys(filename)
            except IOError:
                # for windows
                filename = os.path.expanduser('~/ssh/known_hosts')
                try:
                    self.ssh_client.load_host_keys(filename)
                except IOError:
                    exc_type, exc_value, exc_traceback = sys.exc_info()
                    stacktrace = traceback.extract_tb(exc_traceback)
                    self.logger.critical("Unable to open system host keys file for " + self.host)
                    self.logger.debug(sys.exc_info())
                    self.logger.debug(stacktrace)
                    pass
        else:
            try:
                self.logger.debug("Attempting to load local_hosts keys file " + self.host)
                self.ssh_client.load_host_keys(self.host_key_filename)
            except IOError:
                #print "Unable to open host keys file"
                self.logger.debug("Unable to open local host keys file for " + self.host)
                keyfile = open(self.host_key_filename, 'w+')
                keyfile.close()
                try:
                    self.ssh_client.load_host_keys(self.host_key_filename)
                except IOError:
                    self.logger.debug("Unable to create and load local_hosts keys file for " + self.host)
                    raise
        #needed to compensate for a bug in some versions of paramiko
        self.ssh_client.known_hosts = None

    def ssh_connect(self):
        """
        Connect to SSH Server

        If connection is unsuccessful, one of the following exceptions may be raised

        socket.gaierror     will be raised if the DNS lookup fails
        socket.error        will be raised if there is a TCP/IP problem
        paramiko.AuthenticationException        will be raised if SSH authentication fails
        """

        try:
            self.logger.debug("Opening Connection to " + self.host)
            with conmutex:
                self.ssh_client.connect(self.host, port=self.port, timeout=self.timeout, username=self.username,
                                        password=self.password,
                                        key_filename=self.key_filename, allow_agent=self.allow_agent,
                                        look_for_keys=self.look_for_keys)
        except socket.gaierror:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.critical("Connection Failure for " + self.host + ":  DNS Lookup Failure")
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            self.ssh_client.close()
            raise
        except socket.error:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.critical("Connection Failure for" + self.host + ":  Socket Error")
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            self.ssh_client.close()
            raise
        except paramiko.AuthenticationException:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.critical("Authentication Failure Accessing " + self.host)
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            self.ssh_client.close()
            raise
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.critical("Connection Failure for " + self.host)
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            self.ssh_client.close()
            raise

    @abc.abstractmethod
    def setup_channel(self):
        """Can't do much without a channel.
        Since there are multiple channel options, it is up to the subclass to define this method
        """
        self.ssh_subsystem('xmlagent')

    def ssh_subsystem(self, subsystem):
        """
        Opens channel to SSH server connecting to the specified subsystem
        This would be the equivalent of the -s option from an ssh commandline
        @param subsystem: string indicating the subsystem

        Any exceptions will be logged and returned by a raise command to be caught by higher level
        exception handlers

        """

        self._subsystem = subsystem
        self.logger.debug("Opening channel to " + self.host + " and requesting the " + self._subsystem + " subsystem")
        try:
            self._transport = self.ssh_client.get_transport()
            self._channel = self._transport.open_session()
            self._channel.set_name(self._subsystem)
            self._channel.invoke_subsystem(self._subsystem)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.critical("Failed to connect to " + self._subsystem + " subsystem on host " + self.host)
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            raise

    def ssh_shell(self):
        """
        Opens an SSH shell on the server for interactive sessions

        @raise: Any exceptions will be logged and returned by a raise command to be caught by higher level
        exception handlers
        """

        self.logger.debug("Creating shell to " + self.host)
        try:
            self._transport = self.ssh_client.get_transport()
            self._channel = self.ssh_client.invoke_shell()
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.critical("Failure creating shell for " + self.host)
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            raise

    @checkconnection
    def rpexpect(self, reguexp, code=4,match_count=1,characters=20):
        """

        Method to provide expect-like functionality

        str <- (str)

        -    code 0      Return specified number of characters at end of buffer
        -    code 1      Return specified number of characters at beginning of buffer
        -    code 2      Return TRUE if reguexp found, otherwise return false
        -    code 3      Return contents of buffer if regexp is found, else return false
        -    code 4      continually looks for reguexp in the buffer and returns contents of buffer if found,
                    if not found, times out.  This code must be used with paramiko.

        -    code = 5:  collect characters from channel until timeout is reached
        -    code = 6:  collects the output for batch get request. need to input the number of get requests expected 
                        it will check for same number of delimiters and returns the output.

        reguexp:    string representing the delimeter to look for in the channel

        Looks for the delimeter and returns the preceding string from the socket

        @rtype : str

        The Paramiko timeout, as distinct from the socket timeout, is set to the value of the instance's
        self.command_timeout, which is a property

        The channel is then checked for contents. If there is no content before the command_timeout expires, then
        Paramiko will raise a socket.timeout. This will be logged and re-raised to be caught by a higher level
        handler.

        Content received on the channel is checked for the specified pattern match. If found, the content is returned.

        If not found, the channel will be rechecked periodically for the duration of the command_timeout

        If still not found, or if the remote side closed the channel, one of the following exceptions may be raised
        socket.timeout
        nxos_XML_errors.TimeoutExpiredError
        nxos_XML_errors.ServerClosedChannelError

        """

        buff = ''
        self.logger.debug("rpexpect first block: Timeout is configured as {0}".format(str(self.command_timeout)))
        socket_timeout = socket.getdefaulttimeout()
        self._channel.settimeout(self.command_timeout)
        paramiko_timeout = self._channel.gettimeout()
        self.logger.debug(
            "rpexpect first block: Socket timeout is {0}, {1}".format(str(socket_timeout), str(paramiko_timeout)))
        looptimer = self.command_timeout
        try:
            self.logger.debug("rpexpect first block: Checking buffer for {}".format(self.host))
            buff = self._channel.recv(999999)
            self.logger.debug(
                "rpexpect first block: First buff check in thread {0}, {1}, {2}".format(
                    str(threading.currentThread().getName()), str(
                        thread.get_ident()), str(buff)))
        except socket.timeout:
            self.logger.debug(
                "rpexpect first block: First Timeout waiting for intial response.  Received response:  {0}".format(
                    str(buff)))
            raise

        if int(code) == 0:
            return buff[len(buff) - int(characters):]
        elif int(code) == 1:
            return buff[:int(characters) + 1]
        elif int(code) == 2:
            if re.search(reguexp, buff):
                return True
            else:
                return False
        elif int(code) == 3:
            if re.search(reguexp, buff):
                return buff
            else:
                return False
        elif int(code) == 4:
            start = time.time()
            self.logger.debug("rpexpect type 4 block: Beginning Loop. Buffer so far {}".format(buff))
            while not re.search(reguexp, buff):
                #self.logger.debug("Code 4: Inside while loop in rpexpect in thread ")
                try:
                    resp = self._channel.recv(9999)
                except socket.timeout:
                    self.logger.error(
                        "rpexpect type 4 block: Timedout waiting for intial response.  Received response:  {0}".format(
                            buff))
                    raise socket.timeout(
                        "Socket Timedout waiting for expected response {}.  Received response:  {0}".format(reguexp, buff))
                buff += resp
                #self.logger.debug("Second buff check in thread {0}".format(buff))
                stend = time.time()
                if stend - start < 5:
                    pass
                elif stend - start < looptimer:
                    time.sleep(1)
                    pass
                else:
                    self.logger.error(
                        "rpexpect first type 4 block: Loop Timedout after {} seconds.".format(str(stend - start)))
                    self.logger.debug(
                        "rpexpect type 4 block: Loop Timedout waiting for expected response {}. Received response {}".format(
                            reguexp, buff))
                    raise TimeoutExpiredError(
                        "Loop Timedout waiting for expected response {}. Received response {}".format(reguexp, buff))
                if self._channel.exit_status_ready():
                    self.logger.error(
                        "rpexpect type 4 block: Detected server closed channel while waiting for expected response {}. Received response {0:s}".format(
                            reguexp, buff))
                    self.close()
                    raise ServerClosedChannelError(
                        "Detected server closed channel while waiting for expected response. Received response {}".format(
                            reguexp, buff))

        elif int(code) == 5:
            self.logger.debug("rpexpect type 5 block: Starting Type 5 Processing. Beginning Loop. ")
            start = time.time()
            stend = time.time()
            while stend - start < looptimer:
                time.sleep(1)
                stend = time.time()
                #self.logger.debug("Code 5: Inside while loop in rpexpect in thread ")
                try:
                    resp = self._channel.recv(9999)
                except socket.timeout:
                    self.logger.info(
                        "rpexpect type 5 block: Timedout waiting for intial response.  Received response:  {0}".format(
                            buff))
                buff += resp
                if self._channel.exit_status_ready():
                    self.logger.error(
                        "rpexpect type 5 block: Detected server closed channel while waiting for expected response. Received response {0:s}".format(
                            buff))
                    self.close()
                    raise ServerClosedChannelError(
                        "Detected server closed channel while waiting for expected response. Received response {}".format(
                            buff))

                    #print buff
        elif int(code)==6 :
            self.logger.debug("rpexpect type 6 block: Starting Type 6 Processing. Beginning Loop. ")
            while buff.count(reguexp) < match_count :
                try :
                    resp = self._channel.recv(999999)
                    buff += resp
                except :
                    self.logger.error(
                        "rpexpect type 6 block: Timedout waiting for intial response.  Received response:  {0}".format(
                            buff))
                
        self.logger.debug("rpexpect final block: Returning {}".format(buff))
        return buff

    @checkconnection
    def send(self, message):
        """
        Method for sending message to host
        @type message: str, to be sent to host

        Checks if channel is still open before trying to send.
        """

        self.logger.info("ssh: sending " + message + " to " + self.host)
        try:
            self._channel.send(message)
        except nxos_XML_errors.NotConnectedError:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.critical("Server {} indicates that session has timed out".format(self.host))
            self.logger.error(response)
            self.logger.error(sys.exc_info())
            self.logger.error(stacktrace)
            self.closesession()
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.error("Failure sending message " + message + " to " + self.host)
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
    def close(self):
        """

        Method to close SSH connection to server


        """
        self.logger.debug("SSH: Close ssh session for {}".format(self.host))
        if self._transport is None:
            return
        if self._transport.is_active():
            self._transport.close()
        self._sshconnected = False

    @property
    def sshconnected(self):
        """
        Checks connection status and returns state of the connection when the self.sshconnected attribute is accessed

        @return: Boolean, Status of current connection
        """
        if self._transport is not None:
            self.logger.debug("Prior connection check status:")
            self.logger.debug("sshconnected {} ".format(self._sshconnected))
            self.logger.debug("transport is active {} ".format(self._transport.is_active()))
            self.logger.debug("transport is authenticated {} ".format(self._transport.is_authenticated()))
            self.logger.debug("exit status ready {} ".format(self._channel.exit_status_ready()))
            _sshconnected = self._transport.is_active() and self._transport.is_authenticated() and not self._channel.exit_status_ready()
            if self._sshconnected and not _sshconnected:
                self.close()
            self._sshconnected = _sshconnected
            self.logger.debug("Post connection check status:")
            self.logger.debug("sshconnected {} ".format(self._sshconnected))
            self.logger.debug("transport is active {} ".format(self._transport.is_active()))
            self.logger.debug("transport is authenticated {} ".format(self._transport.is_authenticated()))
            self.logger.debug("exit status ready {} ".format(self._channel.exit_status_ready()))
        return self._sshconnected


    @property
    def command_timeout(self):
        """
        returns the configured command timeout

        @return: command_timeout
        """
        return self._command_timeout

    @command_timeout.setter
    def command_timeout(self, command_timeout):
        """

        Method to change command_timeout

        @param command_timeout: float
        """
        assert isinstance(command_timeout, float) or isinstance(command_timeout, int)
        self._command_timeout = command_timeout


    def nc_sshconnect(self, *args, **kwargs):
        """
        Connect via SSH and initialize the NETCONF session. First attempts the publickey authentication method and then password authentication.

            To disable attempting publickey authentication altogether,
            call with *allow_agent* and *look_for_keys* as `False`.

            Options

            -    *host* is the hostname or IP address to connect to

            -    *port* is by default 22, but some netconf devices use 830

            -    *timeout* is an optional timeout for socket connect

            -    *unknown_host_cb* is the method for handling unknown hosts. Only 'autoaddpolicy' is supported

            -    *username* is the username to use for SSH authentication

            -    *password* is the password used if using password authentication, or the passphrase to use for unlocking keys that require it

            -    *host_key_filename* is a filename where the host keys are located. If *filename* is not specified, looks in the default locations i.e. :file:`~/.ssh/known_hosts` and :file:`~/ssh/known_hosts` for Windows

            -    *key_filename* is a filename where a the private key to be used can be found

            -    *allow_agent* enables querying SSH agent (if found) for keys

            -    *look_for_keys* enables looking in the usual locations for ssh keys (e.g. :file:`~/.ssh/id_*`)

            -    *command_timeout* is the maximum time (float) to wait for a response from the server, 30 second default

                """

        self.sshconnect(host=self.host, *args, **kwargs)

        self.logger.debug("Waiting for hello from host " + self.host)
        self._ncconnected = self.sshconnected
        sessionid=self._netconf_hello()
        #self._generaterpcmessageid()
        return sessionid

    #SSH object requires that the subclass define the object
    def setup_channel(self):
        """
        I need a channel so I can activate the nx-os xml subsystem
        """
        self.ssh_subsystem('netconf')

    #Now I expect to see a hello from the server
    def _netconf_hello(self):
        """
        Looking for hello from server
        Replies with client hello

        Once a connection is opened to the nx-os xmlagent subsystem, thye server should immediately return a
        hello message. This method waits for the hello and parses it for errors.

        If we did not receive a hello, raise XMLError
        If a hello was received, parse and log the capabilities
        If no capabilities in the message, raise XMLError
        Check the message for a session id, if not present raise XMLError

        Construct the client hello, by calling the xmlFunctions.buildclienthello function
        Send client hello to server
        nx-os does not reply to the client hello unless there is an error. This is annoying but compliant
        with the RFC. To account for this, the command_timeout used by ncssh.rpexpect is reset to 5 seconds

        In this case, no response from the server is good so timeouts are not raised to higher level
        handlers

        If there is a response, it is almost certainly an error. Parse to check
        If error, raise NetConfRPCError


        """
        self.logger.debug("NC Hello: Getting Server Hello from " + self.host)
        namespace = "{urn:ietf:params:xml:ns:netconf:base:1.0}"

        try:
            server_hello = self.rpexpect(MSG_DELIM)
            self.logger.info(server_hello)
            server_hello = _stripdelim(server_hello)
        except (nxos_XML_errors.TimeoutExpiredError, socket.timeout):
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.cricital("NC Hello: Timed Out Waiting for Hello from " + self.host)
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            self.close()
            raise

        self.logger.debug(server_hello)
        self.logger.debug("NC Hello: Parsing the XML")
        try:
            root = ET.fromstring(server_hello)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.critical("NC Hello: Failure parsing what should be the Hello from " + self.host)
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            self.close()
            raise

        if 'hello' not in root.tag:
            self.logger.critical("NC Hello: Did not get hello from " + self.host)
            raise XMLError("Did not receive hello from " + self.host)
        capele = [i.text for i in root.iter() if 'capability' in i.tag]
        if len(capele):
            self.server_capabilities = capele
            self.logger.debug("NC Hello: Server Capabilities: {}".format(str(self.server_capabilities)))
        else:
            self.logger.critical("NC Hello: No capabilities in hello message from " + self.host)
            raise XMLError("Did not receive capabilities in the hello message from " + self.host)
        sessele = root.findall(".//" + namespace + "session-id")
        if len(sessele):
            self.sessionid = sessele[0].text
            self.logger.debug("NC Hello: Session ID {} from {}".format(str(self.sessionid), self.host))
        else:
            self.logger.critical("NC Hello: No session-id in the hello message from " + self.host)
            raise XMLError("Did not receive session-id in the hello message from " + self.host)

        self.logger.debug("NC Hello: Construct client hello for " + self.host)

        try:
            client_hello = '''<?xml version="1.0"?>
            <nc:hello xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
              <nc:capabilities>
                <nc:capability>urn:ietf:params:xml:ns:netconf:base:1.0</nc:capability>
              </nc:capabilities>
              </nc:hello>'''

            self.logger.debug("NC Hello: Constructed client hello message " + client_hello)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.critical("NC Hello: Unable to construct client hello to send to " + self.host)
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            raise

        self.logger.debug("NC Hello: Sending client hello to " + self.host)

        response = None
        savetimeout = self.command_timeout

        #nx-os does not reply to the client hello unless there is an error. This is annoying but compliant
        #with the RFC. To account for this, the command_timeout used by ncssh.rpexpect is reset to 5 seconds
        #this five seconds should probably be a global variable or it should be an instance variable made into a
        #property

        try:
            self.send(client_hello + MSG_DELIM)
            #should not see anything from server unless there is an error
            self.logger.debug("NC Hello: Current timeout is configured as " + str(self.command_timeout))
            self.logger.debug("NC Hello: Resetting Paramiko socket timeout to 60 seconds")
            self.command_timeout = 60
            response = self.rpexpect(MSG_DELIM, code=5)
        #A successful client hello should trigger no output from server, so look for socket timeout, which
        # is desirable in this case
        except (socket.timeout, nxos_XML_errors.TimeoutExpiredError):
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.info("NC Hello: Timeout sending client hello to " + self.host)
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.error("NC Hello: Unexpected error sending client hello to " + self.host)
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
        else:
            #if rpexpect returns successfully, we received a message from the server
            #it is probably an error message, so parse to check
            try:
                rpcparse(_stripdelim(response))
            except NetConfRPCError:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                stacktrace = traceback.extract_tb(exc_traceback)
                self.logger.error("Error received from server after sending client hello to " + self.host)
                self.logger.debug(response)
                self.logger.debug(sys.exc_info())
                self.logger.debug(stacktrace)
                raise
        finally:
            self.logger.debug("Resetting Paramiko socket timeout to " + str(savetimeout))
            self.command_timeout = savetimeout
            self.logger.debug("Current timeout is configured as " + str(self.command_timeout))
        return self.sessionid

    def _generaterpcmessageid(self):
        """
        Generates a random number to use as the starting message-id
        """
        self._rpcmessageid = random.randint(1, 1000000)

    @property
    def rpcmessageid(self):
        """

        @rtype : str
        @return: the rpc message id the client is currently using
        """
        if not self._useprovidedmessageid:
            rpcmessageid = str(self._rpcmessageid)
        else:
            rpcmessageid = self._rpcmessageid
        return rpcmessageid
        
    def _closesession(self):
        """
        netconf close-session

        According to NX-OS documentation, the NX-OS server should return a Netconf ok, but in testing, this does
        not always occur. A NotConnectedError exception is raised if the channel closes without
        receiving an RPC ok. Wrap the closesession call in a try...except block

        @return: XML reply from server or None if there is currently no ssh session to a server

        """

        self.logger.debug("Building rpc close-session to send to " + self.host)
        try:
            nxosmessage = '''<rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
                    <close-session/>
                    </rpc>'''
            self.logger.debug("NC: Close Session for {}: {}".format(self.host, nxosmessage))
            return nxosmessage
        except:
            raise

    def closesession(self):
        """
        Sends a netconf close

        @return:None
        """
        try:
            self._closesession()
        finally:
            self._ncconnected = False
            self.close()


    def _send(self, nxosmessage,rpc_parse=1,code=4,match_count=1,rpcmessageid=None):

        """
        Send constructed client rpc message to server

        This method wraps the ncssh.send method and then waits for a response from the server using the ncssh.rpexpect method, which may return one of the following exceptions if there was a problem socket.timeout

        -    nxos_XML_errors.TimeoutExpiredError
        -    nxos_XML_errors.ServerClosedChannelError

        Any exceptions returned by ncssh.rpexpect are reraised

        Once the response is received, it is parsed to check for RPC error, NetConfRPCError, if detected, it is logged but not reraised.

        """

        #send message to server
        self.logger.debug("NC: Sending message to server {}: {}".format(self.host, nxosmessage + MSG_DELIM))
        self.send(nxosmessage + MSG_DELIM)

        #wait for response from server
        self.logger.debug("Waiting for response from server {} ".format(self.host))
        response = None
        try:
            response = self.rpexpect(MSG_DELIM,code,match_count)
            self.logger.debug("NC Send: message from server {}: {}".format(str(response), self.host))
        except nxos_XML_errors.NotConnectedError:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                stacktrace = traceback.extract_tb(exc_traceback)
                self.logger.critical("Server {} indicates that session has timed out".format(self.host))
                self.logger.error(response)
                self.logger.error(sys.exc_info())
                self.logger.error(stacktrace)
                self.closesession()
        except socket.timeout:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.error("Socket timeout waiting for response to rpc message {} to {}".format(nxosmessage, self.host))
            self.logger.debug("NC Send: receive message from server {}: {}".format(str(response), self.host))
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            raise
        except nxos_XML_errors.TimeoutExpiredError:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.error("Loop timeout waiting for response to rpc message {} to {}".format(nxosmessage, self.host))
            self.logger.debug("NC Send: receive message from server {}: {}".format(str(response), self.host))
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            raise
        except nxos_XML_errors.ServerClosedChannelError:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.error("Server closed channel while waiting for response to rpc message {} to {}".format(nxosmessage, self.host))
            self.logger.debug("NC Send: receive message from server {}: {}".format(str(response), self.host))
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            self.closesession()
            #do not propagate exception, closesession will raise one
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.error("Unexpected error while waiting for response to rpc message {} to {}".format(nxosmessage, self.host))
            self.logger.debug("NC Send: receive message from server {}: {}".format(str(response), self.host))
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            raise

        if rpc_parse == 1 :
        #parse response and check for errors
            self.logger.debug("NC Send: Parsing response from {}".format(self.host))
            try:
                response = _stripdelim(response)
                rpcparse(response, rpcmessageid=rpcmessageid)
            except nxos_XML_errors.NetConfRPCError:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                stacktrace = traceback.extract_tb(exc_traceback)
                self.logger.critical("Error received from server after sending client message to " + self.host)
                self.logger.error(response)
                self.logger.error(sys.exc_info())
                self.logger.error(stacktrace)
                raise
            except nxos_XML_errors.NotConnectedError:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                stacktrace = traceback.extract_tb(exc_traceback)
                self.logger.critical("Server {} indicates that session has timed out".format(self.host))
                self.logger.error(response)
                self.logger.error(sys.exc_info())
                self.logger.error(stacktrace)
                self.closesession()

        self.logger.info("Received response from " + self.host + ": " + response)
        return response            
     
        
if __name__ == "__main__":
    LOGFILE = "netconflog.log"
    LOGLEVEL = logging.DEBUG

    logger = logging.getLogger()
    logger.setLevel(LOGLEVEL)
    logformat = logging.Formatter('%(asctime)s: %(threadName)s - %(funcName)s - %(name)s - %(levelname)s - %(message)s')
    logh = logging.FileHandler(LOGFILE)
    logh.setLevel(LOGLEVEL)

    ch = logging.StreamHandler(stream=sys.stdout)
    ch.setLevel(LOGLEVEL)

    logh.setFormatter(logformat)

    ch.setFormatter(logformat)

    logger.addHandler(logh)
    logger.addHandler(ch)

    logger.info("Started")
    nxos = SshConnect('10.104.102.67')
    nxos.nc_sshconnect()
    #nxos.closesession()