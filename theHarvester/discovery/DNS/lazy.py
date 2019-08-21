# $Id: lazy.py,v 1.5.2.1 2007/05/22 20:23:38 customdesigned Exp $
#
# This file is part of the pydns project.
# Homepage: http://pydns.sourceforge.net
#
# This code is covered by the standard Python License.
#

# routines for lazy people.
from theHarvester.discovery.DNS import Base

def revlookup(name):
    "convenience routine for doing a reverse lookup of an address"
    if Base.defaults['server'] == []:
        Base.DiscoverNameServers()
    a = name.split('.')
    a.reverse()
    s = '.'
    b = s.join(a) + '.in-addr.arpa'
    # this will only return one of any records returned.
    return Base.DnsRequest(b, qtype='ptr').req().answers[0]['data']


def mxlookup(name):
    """
    convenience routine for doing an MX lookup of a name. returns a
    sorted list of (preference, mail exchanger) records
    """
    if Base.defaults['server'] == []:
        Base.DiscoverNameServers()
    a = Base.DnsRequest(name, qtype='mx').req().answers
    l = sorted(map(lambda x: x['data'], a))
    return l

#
# $Log: lazy.py,v $
# Revision 1.5.2.1  2007/05/22 20:23:38  customdesigned
# Lazy call to DiscoverNameServers
#
# Revision 1.5  2002/05/06 06:14:38  anthonybaxter
# reformat, move import to top of file.
#
# Revision 1.4  2002/03/19 12:41:33  anthonybaxter
# tabnannied and reindented everything. 4 space indent, no tabs.
# yay.
#
# Revision 1.3  2001/08/09 09:08:55  anthonybaxter
# added identifying header to top of each file
#
# Revision 1.2  2001/07/19 06:57:07  anthony
# cvs keywords added
#
#
