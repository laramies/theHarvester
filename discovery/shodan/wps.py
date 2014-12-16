"""
WiFi Positioning System

Wrappers around the SkyHook and Google Locations APIs to resolve
wireless routers' MAC addresses (BSSID) to physical locations.
"""
try:
    from json import dumps, loads
except:
    from simplejson import dumps, loads
from urllib2 import Request, urlopen
from urllib import urlencode


class Skyhook:

    """Not yet ready for production, use the GoogleLocation class instead."""

    def __init__(self, username='api', realm='shodan'):
        self.username = username
        self.realm = realm
        self.url = 'https://api.skyhookwireless.com/wps2/location'

    def locate(self, mac):
        # Remove the ':'
        mac = mac.replace(':', '')
        print mac
        data = """<?xml version='1.0'?>
        <LocationRQ xmlns='http://skyhookwireless.com/wps/2005' version='2.6' street-address-lookup='full'>
          <authentication version='2.0'>
            <simple>
              <username>%s</username>
              <realm>%s</realm>
            </simple>
          </authentication>
          <access-point>
            <mac>%s</mac>
            <signal-strength>-50</signal-strength>
          </access-point>
        </LocationRQ>""" % (self.username, self.realm, mac)
        request = Request(
            url=self.url,
            data=data,
            headers={'Content-type': 'text/xml'})
        response = urlopen(request)
        result = response.read()
        return result


class GoogleLocation:

    def __init__(self):
        self.url = 'http://www.google.com/loc/json'

    def locate(self, mac):
        data = {
            'version': '1.1.0',
            'request_address': True,
            'wifi_towers': [{
                'mac_address': mac,
                'ssid': 'g',
                'signal_strength': -72
            }]
        }
        response = urlopen(self.url, dumps(data))
        data = response.read()
        return loads(data)
