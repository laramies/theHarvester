#!/usr/bin/env python
# encoding: utf-8
"""
Created by laramies on 2008-08-21.
"""

import socket


class Checker():

    def __init__(self, hosts):
        self.hosts = hosts
        self.realhosts = []

    def check(self):
        for x in self.hosts:
            x = str(x)
            try:
                res = socket.gethostbyname(x)
                res = str(res)
                self.realhosts.append(x + ':' + res)
            except Exception as e:
                self.realhosts.append(x + ':' + 'empty')
        return self.realhosts
