# -*- encoding: utf-8 -*-
"""
 $Id: Type.py,v 1.6.2.1 2007/05/22 20:20:39 customdesigned Exp $

 This file is part of the pydns project.
 Homepage: http://pydns.sourceforge.net

 This code is covered by the standard Python License.

 TYPE values (section 3.2.2)
"""

A = 1           # a host address
NS = 2          # an authoritative name server
MD = 3          # a mail destination (Obsolete - use MX)
MF = 4          # a mail forwarder (Obsolete - use MX)
CNAME = 5       # the canonical name for an alias
SOA = 6         # marks the start of a zone of authority
MB = 7          # a mailbox domain name (EXPERIMENTAL)
MG = 8          # a mail group member (EXPERIMENTAL)
MR = 9          # a mail rename domain name (EXPERIMENTAL)
NULL = 10       # a null RR (EXPERIMENTAL)
WKS = 11        # a well known service description
PTR = 12        # a domain name pointer
HINFO = 13      # host information
MINFO = 14      # mailbox or mail list information
MX = 15         # mail exchange
TXT = 16        # text strings
AAAA = 28       # IPv6 AAAA records (RFC 1886)
SRV = 33        # DNS RR for specifying the location of services (RFC 2782)


# Additional TYPE values from host.c source

UNAME = 110
MP = 240

# QTYPE values (section 3.2.3)

AXFR = 252      # A request for a transfer of an entire zone
MAILB = 253     # A request for mailbox-related records (MB, MG or MR)
MAILA = 254     # A request for mail agent RRs (Obsolete - see MX)
ANY = 255       # A request for all records

# Construct reverse mapping dictionary

_names = dir()
typemap = {}
for _name in _names:
    if _name[0] != '_':
        typemap[eval(_name)] = _name


def typestr(type):
    if type in typemap:
        return typemap[type]
    else:
        return repr(type)
#
# $Log: Type.py,v $
# Revision 1.6.2.1  2007/05/22 20:20:39  customdesigned
# Mark utf-8 encoding
#
# Revision 1.6  2002/03/19 12:41:33  anthonybaxter
# tabnannied and reindented everything. 4 space indent, no tabs.
# yay.
#
# Revision 1.5  2002/03/19 12:26:13  anthonybaxter
# death to leading tabs.
#
# Revision 1.4  2001/08/09 09:08:55  anthonybaxter
# added identifying header to top of each file
#
# Revision 1.3  2001/07/19 07:38:28  anthony
# added type code for SRV. From Michael Ströder.
#
# Revision 1.2  2001/07/19 06:57:07  anthony
# cvs keywords added
#
#
