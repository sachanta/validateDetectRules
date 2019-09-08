#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""
Sample script to print a simple list of all the nodes registered with the controller.
Output format: ``app_name,tier_name,node_name,host_name``
"""

from __future__ import print_function

from appd.cmdline import parse_argv
from appd.request import AppDynamicsClient

__author__ = 'Kyle Furlong'
__copyright__ = 'Copyright (c) 2013-2017 AppDynamics Inc.'


args = parse_argv()
c = AppDynamicsClient(args.url, args.username, args.password, args.account, args.verbose)

resp = c.set_metric_retention(2, 1, 5)
print(resp)
