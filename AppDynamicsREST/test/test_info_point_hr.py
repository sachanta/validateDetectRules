#!/bin/bash

from appd.request import AppDynamicsClient
from appd.time import from_ts, to_ts
from datetime import datetime
from pprint import pprint

appdProduction = AppDynamicsClient('https://fedex1.saas.appdynamics.com', 'RetailRelyAPI', 'F3d#x@M!45', 'fedex1' )

for app in appdProduction.get_applications():
    if 'OFFICE' in app.name:
        appid = app.id
        print(app.name, app.id)

officeNodes = appdProduction.get_nodes(app_id=appid)
hrviolations = appdProduction.get_healthrule_violations(app_id=appid,time_range_type='BEFORE_NOW',duration_in_mins=15)
pprint(hrviolations)
