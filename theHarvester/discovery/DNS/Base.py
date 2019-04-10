"""
$Id: Base.py,v 1.12.2.4 2007/05/22 20:28:31 customdesigned Exp $

This file is part of the pydns project.
Homepage: http://pydns.sourceforge.net

This code is covered by the standard Python License.

    Base functionality. Request and Response classes, that sort of thing.
"""

import socket
import time

from theHarvester.discovery.DNS import Type, Class, Opcode
import asyncore

class DNSError(Exception):
    pass

defaults = {'protocol': 'udp', 'port': 53, 'opcode': Opcode.QUERY,
            'qtype': Type.A, 'rd': 1, 'timing': 1, 'timeout': 30}

defaults['server'] = []


def ParseResolvConf(resolv_path):
    global defaults
    try:
        lines = open(resolv_path).readlines()
    except:
        print('error in path' + resolv_path)
    for line in lines:
        line = line.strip()
        if not line or line[0] == ';' or line[0] == '#':
            continue
        fields = line.split()
        if len(fields) < 2:
            continue
        if fields[0] == 'domain' and len(fields) > 1:
            defaults['domain'] = fields[1]
        if fields[0] == 'search':
            pass
        if fields[0] == 'options':
            pass
        if fields[0] == 'sortlist':
            pass
        if fields[0] == 'nameserver':
            defaults['server'].append(fields[1])


def DiscoverNameServers():
    import sys
    if sys.platform in ('win32', 'nt'):
        import win32dns
        defaults['server'] = win32dns.RegistryResolve()
    else:
        return ParseResolvConf()


class DnsRequest:

    """ high level Request object """

    def __init__(self, *name, **args):
        self.donefunc = None
        #fix maybe?
        self.asyn = False
        #self.async = None #TODO FIX async is a keyword
        self.defaults = {}
        self.argparse(name, args)
        self.defaults = self.args

    def argparse(self, name, args):
        if not name and 'name' in self.defaults:
            args['name'] = self.defaults['name']
        if isinstance(name, str):
            args['name'] = name
        else:
            if len(name) == 1:
                if name[0]:
                    args['name'] = name[0]
        for i in defaults.keys():
            if i not in args:
                if i in self.defaults:
                    args[i] = self.defaults[i]
                else:
                    args[i] = defaults[i]
        if isinstance(args['server'], str):
            args['server'] = [args['server']]
        self.args = args

    def socketInit(self, a, b):
        self.s = socket.socket(a, b)

    def processUDPReply(self):
        import time
        import select
        if self.args['timeout'] > 0:
            r, w, e = select.select([self.s], [], [], self.args['timeout'])
            if not len(r):
                raise DNSError('Timeout')
        self.reply = self.s.recv(1024)
        self.time_finish = time.time()
        self.args['server'] = self.ns
        return self.processReply()

    def processTCPReply(self):
        import time
        from theHarvester.discovery.DNS import Lib
        self.f = self.s.makefile('r')
        header = self.f.read(2)
        if len(header) < 2:
            raise DNSError('EOF')
        count = Lib.unpack16bit(header)
        self.reply = self.f.read(count)
        if len(self.reply) != count:
            raise DNSError('incomplete reply')
        self.time_finish = time.time()
        self.args['server'] = self.ns
        return self.processReply()

    def processReply(self):
        from theHarvester.discovery.DNS import Lib
        self.args['elapsed'] = (self.time_finish - self.time_start) * 1000
        u = Lib.Munpacker(self.reply)
        r = Lib.DnsResult(u, self.args)
        r.args = self.args
        # self.args=None  # mark this DnsRequest object as used.
        return r
        #### TODO TODO TODO ####
#        if protocol == 'tcp' and qtype == Type.AXFR:
#            while 1:
#                header = f.read(2)
#                if len(header) < 2:
#                    print '========== EOF =========='
#                    break
#                count = Lib.unpack16bit(header)
#                if not count:
#                    print '========== ZERO COUNT =========='
#                    break
#                print '========== NEXT =========='
#                reply = f.read(count)
#                if len(reply) != count:
#                    print '*** Incomplete reply ***'
#                    break
#                u = Lib.Munpacker(reply)
#                Lib.dumpM(u)

    def conn(self):
        self.s.connect((str(self.ns), self.port))


    def req(self, *name, **args):
        " needs a refactoring "
        import time
        from theHarvester.discovery.DNS import Lib
        self.argparse(name, args)
        # if not self.args:
        #    raise DNSError,'reinitialize request before reuse'
        protocol = self.args['protocol']
        self.port = self.args['port']
        opcode = self.args['opcode']
        rd = self.args['rd']
        server = self.args['server']
        if isinstance(self.args['qtype'], str):
            try:
                qtype = getattr(Type, str.upper(self.args['qtype']))
            except AttributeError:
                raise DNSError('unknown query type')
        else:
            qtype = self.args['qtype']
        if 'name' not in self.args:
            print(self.args)
            raise DNSError('nothing to lookup')
        qname = self.args['name']
        if qtype == Type.AXFR:
            print('Query type AXFR, protocol forced to TCP')
            protocol = 'tcp'
        # print 'QTYPE %d(%s)' % (qtype, Type.typestr(qtype))
        m = Lib.Mpacker()
        # jesus. keywords and default args would be good. TODO.
        m.addHeader(0,
                    0, opcode, 0, 0, rd, 0, 0, 0,
                    1, 0, 0, 0)
        m.addQuestion(qname, qtype, Class.IN)
        self.request = m.getbuf()
        try:
            if protocol == 'udp':
                self.sendUDPRequest(server)
            else:
                self.sendTCPRequest(server)
        except socket.error as reason:
            raise DNSError(reason)
        if self.asyn:
            return None
        else:
            return self.response

    def sendUDPRequest(self, server):
        "refactor me"
        self.response = None
        self.socketInit(socket.AF_INET, socket.SOCK_DGRAM)
        for self.ns in server:
            try:
                # TODO. Handle timeouts &c correctly (RFC)
                #self.s.connect((self.ns, self.port))
                self.conn()
                self.time_start = time.time()
                if not self.asyn:
                    self.s.send(self.request)
                    self.response = self.processUDPReply()
            # except socket.error:
            except Exception as e:
                print(e)
                continue
            break
        if not self.response:
            if not self.asyn:
                raise DNSError('no working nameservers found')

    def sendTCPRequest(self, server):
        " do the work of sending a TCP request "
        import time
        import theHarvester.discovery.DNS.Lib as Lib
        self.response = None
        for self.ns in server:
            try:
                self.socketInit(socket.AF_INET, socket.SOCK_STREAM)
                self.time_start = time.time()
                self.conn()
                self.s.send(Lib.pack16bit(len(self.request)) + self.request)
                self.s.shutdown(1)
                self.response = self.processTCPReply()
            except socket.error:
                continue
            break
        if not self.response:
            raise DNSError('no working nameservers found')
# class DnsAsyncRequest(DnsRequest):


class DnsAsyncRequest(DnsRequest, asyncore.dispatcher_with_send):

    " an asynchronous request object. out of date, probably broken "

    def __init__(self, *name, **args):
        DnsRequest.__init__(self, *name, **args)
        # XXX todo
        if 'done' in args and args['done']:
            self.donefunc = args['done']
        else:
            self.donefunc = self.showResult
        # self.realinit(name,args) # XXX todo
        self.asyn = True

    def conn(self):
        import time
        self.connect((self.ns, self.port))
        self.time_start = time.time()
        if 'start' in self.args and self.args['start']:
            asyncore.dispatcher.go(self)

    def socketInit(self, a, b):
        self.create_socket(a, b)
        asyncore.dispatcher.__init__(self)
        self.s = self

    def handle_read(self):
        if self.args['protocol'] == 'udp':
            self.response = self.processUDPReply()
            if self.donefunc:
                self.donefunc(*(self,))

    def handle_connect(self):
        self.send(self.request)

    def handle_write(self):
        pass

    def showResult(self, *s):
        self.response.show()

#
# $Log: Base.py,v $
# Revision 1.12.2.4  2007/05/22 20:28:31  customdesigned
# Missing import Lib
#
# Revision 1.12.2.3  2007/05/22 20:25:52  customdesigned
# Use socket.inetntoa,inetaton.
#
# Revision 1.12.2.2  2007/05/22 20:21:46  customdesigned
# Trap socket error
#
# Revision 1.12.2.1  2007/05/22 20:19:35  customdesigned
# Skip bogus but non-empty lines in resolv.conf
#
# Revision 1.12  2002/04/23 06:04:27  anthonybaxter
# attempt to refactor the DNSRequest.req method a little. after doing a bit
# of this, I've decided to bite the bullet and just rewrite the puppy. will
# be checkin in some design notes, then unit tests and then writing the sod.
#
# Revision 1.11  2002/03/19 13:05:02  anthonybaxter
# converted to class based exceptions (there goes the python1.4 compatibility :)
#
# removed a quite gross use of 'eval()'.
#
# Revision 1.10  2002/03/19 12:41:33  anthonybaxter
# tabnannied and reindented everything. 4 space indent, no tabs.
# yay.
#
# Revision 1.9  2002/03/19 12:26:13  anthonybaxter
# death to leading tabs.
#
# Revision 1.8  2002/03/19 10:30:33  anthonybaxter
# first round of major bits and pieces. The major stuff here (summarised
# from my local, off-net CVS server :/ this will cause some oddities with
# the
#
# tests/testPackers.py:
#   a large slab of unit tests for the packer and unpacker code in DNS.Lib
#
# DNS/Lib.py:
#   placeholder for addSRV.
#   added 'klass' to addA, make it the same as the other A* records.
#   made addTXT check for being passed a string, turn it into a length 1 list.
#   explicitly check for adding a string of length > 255 (prohibited).
#   a bunch of cleanups from a first pass with pychecker
#   new code for pack/unpack. the bitwise stuff uses struct, for a smallish
#     (disappointly small, actually) improvement, while addr2bin is much
#     much faster now.
#
# DNS/Base.py:
#   added DiscoverNameServers. This automatically does the right thing
#     on unix/ win32. No idea how MacOS handles this.  *sigh*
#     Incompatible change: Don't use ParseResolvConf on non-unix, use this
#     function, instead!
#   a bunch of cleanups from a first pass with pychecker
#
# Revision 1.5  2001/08/09 09:22:28  anthonybaxter
# added what I hope is win32 resolver lookup support. I'll need to try
# and figure out how to get the CVS checkout onto my windows machine to
# make sure it works (wow, doing something other than games on the
# windows machine :)
#
# Code from Wolfgang.Strobl@gmd.de
# win32dns.py from
# http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/66260
#
# Really, ParseResolvConf() should be renamed "FindNameServers" or
# some such.
#
# Revision 1.4  2001/08/09 09:08:55  anthonybaxter
# added identifying header to top of each file
#
# Revision 1.3  2001/07/19 07:20:12  anthony
# Handle blank resolv.conf lines.
# Patch from Bastian Kleineidam
#
# Revision 1.2  2001/07/19 06:57:07  anthony
# cvs keywords added
#
#
