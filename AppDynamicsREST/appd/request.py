"""
This module contains the main classes for handling requests to the AppDynamics REST API.
"""

from __future__ import print_function

import sys
import json
import requests

from datetime import datetime

from model.account import *
from model.application import *
from model.config_variable import *
from model.license_module import *
from model.hourly_license_usage import *
from model.license_usage import *
from model.tier import *
from model.backend import *
from model.metric_treenode import *
from model.business_transaction import *
from model.policy_violation import *
from model.snapshot import *
from model.metric_data import *
from model.node import *
from model.set_controller_url import *
from model.event import *
from model.action_suppressions import *
from model.audit_history import *


class AppDynamicsClient(object):
    """
    Main class that wraps around the REST API to make it easier to send requests
    and parse responses.
    """

    TIME_RANGE_TYPES = ('BEFORE_NOW', 'BEFORE_TIME', 'AFTER_TIME', 'BETWEEN_TIMES')

    DEEP_DIVE_POLICIES = ('SLA_FAILURE', 'TIME_SAMPLING', 'ERROR_SAMPLING', 'OCCURRENCE_SAMPLING',
                          'ON_DEMAND', 'HOTSPOT', 'HOTSPOT_LEARN', 'APPLICATION_STARTUP', 'DIAGNOSTIC_SESSION',
                          'SLOW_DIAGNOSTIC_SESSION', 'ERROR_DIAGNOSTIC_SESSION', 'POLICY_FAILURE_DIAGNOSTIC_SESSION',
                          'INFLIGHT_SLOW_SESSION')

    USER_EXPERIENCES = ('NORMAL', 'SLOW', 'VERY_SLOW', 'STALL', 'BUSINESS_ERROR')

    COLLECTOR_TYPES = ('ERROR_IDS', 'STACK_TRACES', 'ERROR_DETAIL', 'HTTP_PARAMETER', 'BUSINESS_DATA',
                       'COOKIE', 'HTTP_HEADER', 'SESSION_KEY', 'RESPONSE_HEADER', 'LOG_MESSAGE',
                       'TRANSACTION_PROPERTY', 'TRANSACTION_EVENT', 'DOTNET_PROPS', 'DOTNET_SET')

    SNAPSHOT_REQUEST_PARAMS = ('guids', 'archived', 'deep-dive-policy', 'application-component-ids',
                               'application-component-node-ids', 'business-transaction-ids', 'user-experience',
                               'first-in-chain', 'need-props', 'need-exit-calls', 'execution-time-in-millis',
                               'session-id', 'user-principal-id', 'error-ids', 'error-occurred',
                               'bad-request', 'diagnostic-snapshot', 'diagnostic-session-guid',
                               'starting-request-id', 'ending-request-id',
                               'data-collector-name', 'data-collector-type', 'data-collector-value')

    SNAPSHOT_REQUEST_LISTS = ('business-transaction-ids', 'user-experience', 'error-ids', 'guids', 'deep-dive-policy',
                              'application-component-ids', 'application-component-node-ids', 'diagnostic-session-guid')

    CPM = CALLS_PER_MINUTE = 'Calls per Minute'
    ART = AVERAGE_RESPONSE_TIME = 'Average Response Time (ms)'
    NORMAL_ART = 'Normal Average Response Time (ms)'
    SLOW_CALLS = 'Number of Slow Calls'
    VERY_SLOW_CALLS = 'Number of Very Slow Calls'
    EPM = ERRORS_PER_MINUTE = 'Errors per Minute'
    EXCEPTIONS_PER_MINUTE = 'Exceptions per Minute'
    STALLS = 'Stall Count'

    def __init__(self, base_url='http://localhost:8090', username='user1', password='welcome',
                 account='customer1', debug=False, verify=True):
        """
        Creates a new instance of the client.

        :param base_url: URL of your controller.
        :type base_url: str.
        :param username: User name to authenticate to the controller with.
        :type username: str.
        :param password: Password for authentication to the controller.
        :type password: str.
        :param account: Account name for multi-tenant controllers. For single-tenant controllers, use
                        the default value of "customer1".
        :param debug: Set to :const:`True` to print extra debugging information to :const:`sys.stdout`.
        :type debug: bool.
        """

        self._username, self._password, self._account, self._app_id, self._session = '', '', '', None, None
        self._base_url = ''
        (self.base_url, self.username, self.password, self.account, self.debug, self.verify) = (base_url, username, password,
                                                                                   account, debug, verify)

    @property
    def base_url(self):
        return self._base_url

    @base_url.setter
    def base_url(self, new_url):
        self._base_url = new_url
        if '://' not in self._base_url:
            self._base_url = 'http://' + self._base_url
        while self._base_url.endswith('/'):
            self._base_url = self._base_url[:-1]

    def __make_auth(self):
        self._auth = (self._username + '@' + self._account, self._password)

    @property
    def username(self):
        return self._username

    @username.setter
    def username(self, new_username):
        self._username = new_username
        self.__make_auth()

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, new_password):
        self._password = new_password
        self.__make_auth()

    @property
    def account(self):
        return self._account

    @account.setter
    def account(self, new_account):
        self._account = new_account
        self.__make_auth()

    @property
    def app_id(self):
        return self._app_id

    @app_id.setter
    def app_id(self, new_app_id):
        self._app_id = new_app_id

    def _get_session(self):
        if not self._session:
            from requests.sessions import Session
            self._session = Session()
            self._session.verify = self.verify
        return self._session

    def upload(self, path, data, filename='default'):
        """
        Workaround a bug between requests file upload boundary format
        and the expected format at the server
        """

        import pycurl
        import base64
        try:
            from io import BytesIO
        except ImportError:
            from StringIO import StringIO as BytesIO

        if not path.startswith('/'):
            path = '/' + path
        url = self._base_url + path

        c = pycurl.Curl()
        b = BytesIO()

        c.setopt(c.WRITEDATA, b)
        c.setopt(c.URL, url)

        auth = base64.encodestring('%s:%s' % self._auth).replace('\n', '')

        c.setopt(c.HTTPHEADER, [
            'Authorization: Basic {0}'.format(auth)
        ])
        c.setopt(c.HTTPPOST, [
            ('fileupload', (
                c.FORM_BUFFER, filename,
                c.FORM_BUFFERPTR, data,
            )),
        ])

        c.perform()
        c.close()

        return b.getvalue()

    def request(self, path, params=None, method='GET', use_json=True, query=True, headers=None):
        if not path.startswith('/'):
            path = '/' + path
        url = self._base_url + path

        params = params or {}
        if use_json and method == 'GET':
            params['output'] = 'JSON'
        for k in list(params.keys()):
            if params[k] is None:
                del params[k]

        if self.debug:
            print('Retrieving ' + url, self._auth, params)

        if method == 'GET' or query:
            r = self._get_session().request(method, url, auth=self._auth, params=params, headers=headers)
        else:
            if not headers:
                headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
            r = self._get_session().request(method, url, auth=self._auth, data=json.dumps(params), headers=headers)

        if r.status_code != requests.codes.ok:
            print(url, file=sys.stderr)
            r.raise_for_status()

        return r.json() if use_json else r.text

    def _app_path(self, app_id, path=None):
        app_id = app_id if isinstance(app_id, int) or isinstance(app_id, str) else self._app_id
        if not app_id:
            raise ValueError('application id is required')
        path = '/controller/rest/applications/%s' % app_id + (path or '')
        return path

    def get_metric_tree(self, app_id=None, metric_path=None, recurse=False):
        """
        Retrieves a list of available metrics.

        :param int app_id: Application ID to retrieve metrics for. If :const:`None`, the value stored in the
          `app_id` property will be used.
        :param str metric_path: Point in the metric tree at which you want to retrieve the available metrics.
          If :const:`None`, start at the root.
        :param bool recurse: If :const:`True`, retrieve the entire tree from :data:`metric_path` on down.
        :returns: An object containing the metrics under this point in the tree.
        :rtype: model.MetricTreeNodes
        """
        parent = None
        if metric_path:
            parent = MetricTreeNode(parent=None, node_name=metric_path, node_type='folder')
        return self._get_metric_tree(app_id, parent=parent, recurse=recurse)

    def _get_metric_tree(self, app_id=None, parent=None, recurse=False):
        params = {}
        if parent:
            params['metric-path'] = parent.path
        path = '/applications/%d/metrics' % app_id
        nodes = MetricTreeNodes.from_json(self.request(path, params), parent)
        if recurse:
            for node in nodes:
                if node.type == 'folder':
                    self._get_metric_tree(app_id, parent=node, recurse=True)
        return nodes

    # Top-level requests

    def _top_request(self, cls, path, params=None, method='GET', query=True):
        return cls.from_json(self.request('/controller/rest' + path, params, method, query=query))

    def set_controller_url(self, controllerURL):
        """
        Sets the base url for all email notification links

        :param str controller_url: Base URL to use for email notification links
        :returns: Success message
        """
        param = {'controllerURL': controllerURL}
        return self._top_request(SetControllerUrlResponse,
                                 '/accounts/%s/update-controller-url' % self.account, param, 'POST', query=False)

    def get_audit_history(self, start_time, end_time, time_zone_id=None):
        """
        Gathers audit history for up to a 24h time period

        :param str start_time: Start time in the format: "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
        :param str end_time: End time in the format: "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
        :param str time_zone_id: Optional, time zone in tz format

        :return: A :class:`AuditHistory <model.AuditHistory>` object, representing a collection of audits.
        :rtype: model.AuditHistory
        """

        params = {
            'startTime': start_time,
            'endTime': end_time
        }

        if (time_zone_id):
            params.update({'timeZoneId': time_zone_id})

        return AuditHistory.from_json(self.request('/controller/ControllerAuditHistory',
                                                   params, 'GET', query=True, use_json=True))

    def create_user(self,
                    user_name,
                    user_display_name,
                    user_email,
                    user_password,
                    user_roles=None):
        """
        Creates a user

        :param str user_name: User's name (required)
        :param str user_display_name: How the user's name will show up in the UI (required)
        :param str user_email: User's email (required)
        :param str user_roles: Comma-separated list of roles
            https://docs.appdynamics.com/display/PRO42/Roles+and+Permissions#RolesandPermissions-PredefinedRoles
        :param str user_password: Required on create, not on update

        :returns: Nothing on success, exception with HTTP error code on failure
        """
        params = {'user-name': user_name,
                  'user-display-name': user_display_name,
                  'user-email': user_email}

        if (user_roles):
            params.update({'user-roles': user_roles})

        if (user_password):
            params.update({'user-password': user_password})

        return self.request('/controller/rest/users', params, 'POST', query=True, use_json=False)

    def export_health_rules(self, application_id, name=None):
        """
        Exports all health rules from the given app, in XML format

        :param int application_id: Application ID
        :param string name: Name of a particular health rule to export,
            if omitted, all health rules will be exported
        :returns: JSON string
        """
        params = {}
        if (name):
            params.update({'name': name})

        return self.request('/controller/healthrules/{0}'.format(application_id),
                            params, 'GET', query=True, use_json=False)

    def import_health_rules(self, application_id, xml, overwrite=False):
        """
        Imports all health rules into the given app, from XML format

        :param int application_id: Application ID
        :param string xml: Output of export_health_rules

        :returns: Plain text string, containing success or failure messages
        """

        params = {}
        if (overwrite):
            params.update({'overwrite': overwrite})

        path = '/controller/healthrules/{0}'.format(application_id)

        if not path.startswith('/'):
            path = '/' + path
        url = self._base_url + path

        files = {'file': ('healthrules.xml', xml)}
        r = self._get_session().request('POST', url, auth=self._auth, params=params, files=files)
        return r.text

    def export_entry_point_type(self, application_id, entry_point_type, rule_type, tier=None, rule_name=None):
        """
        Exports one entry point type from the given app, in XML format

        :param int application_id: Application ID
        :param string entry_point_type: type of entry point, see AppDynamics docs
        :param string rule_type: one of auto, custom, or exclude
        :param string tier: name of the tier to export from, optional

        :returns: XML string
        """
        url = '/controller/transactiondetection/{0}/'.format(application_id)

        if (tier):
            url = url + tier + '/'

        url = url + rule_type + '/'
        url = url + entry_point_type

        if (rule_name):
            url = url + '/' + rule_name

        return self.request(url, {}, 'GET', query=True, use_json=False)

    def import_entry_point_type(self, application_id, entry_point_type, rule_type, xml, tier=None, rule_name=None):
        """
        Imports all entry points into the given app, from XML format

        :param int application_id: Application ID
        :param string rule_type: one of auto, custom, or exclude
        :param string xml: Output of export_entry_points
        :param string tier: name of the tier to export from, optional

        :returns: JSON string, containing success or failure messages
        """

        path = '/controller/transactiondetection/{0}/'.format(application_id)

        if (tier):
            path = path + tier + '/'

        path = path + rule_type + '/'
        path = path + entry_point_type

        if (rule_name):
            path = path + '/' + rule_name

        if not path.startswith('/'):
            path = '/' + path
        url = self._base_url + path

        files = {'file': ('entrypoints.xml', xml)}
        r = self._get_session().request('POST', url, auth=self._auth, files=files)
        return r.text

    def export_entry_points(self, application_id, rule_type, tier=None):
        """
        Exports all entry points from the given app, in XML format

        :param int application_id: Application ID
        :param string rule_type: one of auto, custom, or exclude
        :param string tier: name of the tier to export from, optional

        :returns: XML string
        """
        url = '/controller/transactiondetection/{0}/'.format(application_id)

        if (tier):
            url = url + tier + '/'

        url = url + rule_type

        return self.request(url, {}, 'GET', query=True, use_json=False)

    def import_entry_points(self, application_id, rule_type, xml, tier=None):
        """
        Imports all entry points into the given app, from XML format

        :param int application_id: Application ID
        :param string rule_type: one of auto, custom, or exclude
        :param string xml: Output of export_entry_points
        :param string tier: name of the tier to export from, optional

        :returns: JSON string, containing success or failure messages
        """

        path = '/controller/transactiondetection/{0}/'.format(application_id)

        if (tier):
            path = path + tier + '/'

        path = path + rule_type

        if not path.startswith('/'):
            path = '/' + path
        url = self._base_url + path

        files = {'file': ('entrypoints.xml', xml)}
        r = self._get_session().request('POST', url, auth=self._auth, files=files)
        return r.text

    def export_analytics_dynamic_service_configs(self, application_id):
        """
        Exports all analytics dynamics service configs from the given app, in XML format
        Only available on controllers 4.3+

        :param int application_id: Application ID

        :returns: JSON string
        """

        return self.request('/controller/analyticsdynamicservice/{0}'.format(application_id),
                            {}, 'GET', query=True, use_json=False)

    def import_analytics_dynamic_service_configs(self, application_id, xml):
        """
        Imports all actions into the given app, from JSON format
        Only available on controllers 4.3+

        :param int application_id: Application ID
        :param string xml: Output of export_analytics_dynamic_service_configs

        :returns: JSON string, containing success or failure messages
        """

        path = '/controller/analyticsdynamicservice/{0}'.format(application_id)

        if not path.startswith('/'):
            path = '/' + path
        url = self._base_url + path

        files = {'file': ('actions.xml', xml)}
        r = self._get_session().request('POST', url, auth=self._auth, files=files)
        return r.text

    def get_errordetectionrules(self):

        url = self._base_url + '/controller/restui/applicationManagerUiBean/applicationConfiguration/19984'
        files = {'file': ('errordetect.json', json)}
        return self._get_session().request('GET', url, auth=self._auth)

    def export_custom_dashboard(self, dashboard_id):
        """
        Exports custom dashboard with the given ID, in JSON format

        :param int dashboard_id: custom dashboard ID

        :returns: JSON string
        """

        params = {}
        if (dashboard_id):
            params.update({'dashboardId': dashboard_id})

        return self.request('/controller/CustomDashboardImportExportServlet', params, 'GET', query=True, use_json=False)

    def import_custom_dashboard(self, json):
        """
        Imports custom dashboard, from JSON format

        :param string json: Output of export_custom_dashboard

        :returns: JSON string, containing success or failure messages
        """

        path = '/controller/CustomDashboardImportExportServlet'

        return self.upload(path, json)

    def export_policies(self, application_id):
        """
        Exports all policies from the given app, in JSON format

        :param int application_id: Application ID

        :returns: JSON string
        """

        return self.request('/controller/actions/{0}'.format(application_id), {}, 'GET', query=True, use_json=False)

    def import_policies(self, application_id, json):
        """
        Imports all policies into the given app, from JSON format

        :param int application_id: Application ID
        :param string json: Output of export_policies

        :returns: JSON string, containing success or failure messages
        """

        path = '/controller/actions/{0}'.format(application_id)

        return self.upload(path, json)

    def export_actions(self, application_id):
        """
        Exports all actions from the given app, in JSON format

        :param int application_id: Application ID

        :returns: JSON string
        """

        return self.request('/controller/actions/{0}'.format(application_id), {}, 'GET', query=True, use_json=False)

    def import_actions(self, application_id, json):
        """
        Imports all actions into the given app, from JSON format

        :param int application_id: Application ID
        :param string json: Output of export_actions

        :returns: JSON string, containing success or failure messages
        """

        path = '/controller/actions/{0}'.format(application_id)

        if not path.startswith('/'):
            path = '/' + path
        url = self._base_url + path

        files = {'file': ('actions.json', json)}
        r = self._get_session().request('POST', url, auth=self._auth, files=files)
        return r.text

    def export_email_action_templates(self):
        """
        Exports all email action templates from the controller, in JSON format

        :returns: JSON string
        """

        return self.request('/controller/actiontemplate/email', {}, 'GET', query=True, use_json=False)

    def import_email_action_templates(self, json):
        """
        Imports all email action templates into the controller, from JSON format

        :param string json: Output of export_email_action_templates

        :returns: JSON string, containing success or failure messages
        """

        path = '/controller/actiontemplate/email'

        if not path.startswith('/'):
            path = '/' + path
        url = self._base_url + path

        files = {'file': ('actions.json', json)}
        r = self._get_session().request('POST', url, auth=self._auth, files=files)
        return r.text

    def export_httprequest_action_templates(self):
        """
        Exports all httprequest action templates from the controller, in JSON format

        :returns: JSON string
        """

        return self.request('/controller/actiontemplate/httprequest', {}, 'GET', query=True, use_json=False)

    def import_httprequest_action_templates(self, json):
        """
        Imports all httprequest action templates into the controller, from JSON format

        :param string json: Output of export_httprequest_action_templates

        :returns: JSON string, containing success or failure messages
        """

        path = '/controller/actiontemplate/httprequest'

        if not path.startswith('/'):
            path = '/' + path
        url = self._base_url + path

        files = {'file': ('actions.json', json)}
        r = self._get_session().request('POST', url, auth=self._auth, files=files)
        return r.text

    def get_config(self):
        """
        Retrieve the controller configuration.

        :returns: Configuration variables.
        :rtype: model.ConfigVariables
        """
        return self._top_request(ConfigVariables, '/configuration')

    def set_config(self, name, value):
        """
        Set a controller configuration value.

        :returns: Configuration variables.
        :rtype: model.ConfigVariables
        """
        param = {'name': name, 'value': value}
        return self._top_request(ConfigVariables, '/configuration', param, 'POST', query=True)

    def get_applications(self):
        """
        Get a list of all business applications.

        :returns: List of applications visible to the user.
        :rtype: model.Applications
        """
        return self._top_request(Applications, '/applications')

    def mark_nodes_historical(self, nodes):
        """
        Mark nodes historical

        :param str nodes: CSV of node IDs

        :returns: Nothing on success, exception with HTTP error code on failure
        """
        params = {'application-component-node-ids': nodes}

        return self.request('/controller/rest/mark-nodes-historical', params, 'POST', query=True, use_json=False)

    # Application-level requests

    def _app_request(self, cls, path, app_id=None, params=None, method='GET', query=True, use_json=True):
        path = self._app_path(app_id, path)
        return cls.from_json(self.request(path, params, method=method, query=query, use_json=use_json))

    def get_bt_list(self, app_id=None, excluded=False):
        """
        Get the list of all registered business transactions in an application.

        :param int app_id: Application ID to retrieve the BT list for. If :const:`None`, the value stored in the
          `app_id` property will be used.
        :param bool excluded: If True, the function will return BT's that have been excluded in the AppDynamics
          UI. If False, the function will return all BT's that have not been excluded. The default is False.
        :returns: The list of registered business transactions.
        :rtype: model.BusinessTransactions
        """
        return self._app_request(BusinessTransactions, '/business-transactions', app_id, {'exclude': excluded})

    def get_backends(self, app_id=None):
        """
        Get the list of all backends in an application.

        :param int app_id: Application ID to retrieve backends for. If :const:`None`, the value stored in the
          `app_id` property will be used.
        :return: A :class:`Backends <model.Backends>` object, representing a collection of backends.
        :rtype: model.Backends
        """
        return self._app_request(Backends, '/backends', app_id)

    def get_tiers(self, app_id=None):
        """
        Get the list of all configured tiers in an application.

        :param int app_id: Application ID to retrieve tiers for. If :const:`None`, the value stored in the
          `app_id` property will be used.
        :return: A :class:`Tiers <model.Tiers>` object, representing a collection of tiers.
        :rtype: model.Tiers
        """
        return self._app_request(Tiers, '/tiers', app_id)

    def get_nodes(self, app_id=None, tier_id=None):
        """
        Retrieves the list of nodes in the application, optionally filtered by tier.

        :param int app_id: Application ID to retrieve nodes for. If :const:`None`, the value stored in the
          `app_id` property will be used.
        :param int tier_id: If set, retrieve only the nodes belonging to the specified tier. If :const:`None`,
          retrieve all nodes in the application.
        :return: A :class:`Nodes <model.Nodes>` object, representing a collection of nodes.
        :rtype: model.Nodes
        """

        path = ('/tiers/%s/nodes' % tier_id) if tier_id else '/nodes'
        return self._app_request(Nodes, path, app_id)

    def get_node(self, node_id, app_id=None):
        """
        Retrieves details about a single node.

        :param node_id: ID or name of the node to retrieve.
        :param app_id: Application ID to search for the node.
        :return: A single Node object.
        :rtype: model.Node
        """
        return self._app_request(Node, '/nodes/%s' % node_id, app_id)

    def _validate_time_range(self, time_range_type, duration_in_mins, start_time, end_time):

        """
        Validates the combination of parameters used to specify a time range in AppDynamics.

        :param str time_range_type: type of time range to search
        :param int duration_in_mins: duration to search, in minutes
        :param long start_time: starting time
        :param long end_time: ending time
        :returns: parameters to be sent to controller
        :rtype: dict
        """
        if time_range_type and time_range_type not in self.TIME_RANGE_TYPES:
            raise ValueError('time_range_time must be one of: ' + ', '.join(self.TIME_RANGE_TYPES))

        elif time_range_type == 'BEFORE_NOW' and not duration_in_mins:
            raise ValueError('when using BEFORE_NOW, you must specify duration_in_mins')

        elif time_range_type == 'BEFORE_TIME' and (not end_time or not duration_in_mins):
            raise ValueError('when using BEFORE_TIME, you must specify duration_in_mins and end_time')

        elif time_range_type == 'AFTER_TIME' and (not start_time or not duration_in_mins):
            raise ValueError('when using AFTER_TIME, you must specify duration_in_mins and start_time')

        elif time_range_type == 'BETWEEN_TIMES' and (not start_time or not end_time):
            raise ValueError('when using BETWEEN_TIMES, you must specify start_time and end_time')

        return {'time-range-type': time_range_type,
                'duration-in-mins': duration_in_mins,
                'start-time': start_time,
                'end-time': end_time}

    def get_metrics(self, metric_path, app_id=None, time_range_type='BEFORE_NOW',
                    duration_in_mins=15, start_time=None, end_time=None, rollup=True):
        """
        Retrieves metric data.

        :param str metric_path: Full metric path of the metric(s) to be retrieved. Wildcards are supported.
            See :ref:`metric-paths` for details.
        :param int app_id: Application ID to retrieve nodes for. If :const:`None`, the value stored in the
            `app_id` property will be used.
        :param str time_range_type: Must be one of :const:`BEFORE_NOW`, :const:`BEFORE_TIME`,
            :const:`AFTER_TIME`, or :const:`BETWEEN_TIMES`.
            See :ref:`time-range-types` for a full explanation.
        :param int duration_in_mins: Number of minutes before now. Only valid if the
            :attr:`time_range_type` is :const:`BEFORE_NOW`.
        :param long start_time: Start time, expressed in milliseconds since epoch. Only valid if the
            :attr:`time_range_type` is :const:`AFTER_TIME` or :const:`BETWEEN_TIMES`.
        :param long end_time: End time, expressed in milliseconds since epoch. Only valid if the
            :attr:`time_range_type` is :const:`BEFORE_TIME` or :const:`BETWEEN_TIMES`.
        :param bool rollup: If :const:`False`, return individual data points for each time slice in
            the given time range. If :const:`True`, aggregates the data and returns a single data point.
        :returns: A list of metric values.
        :rtype: model.MetricData
        """

        params = self._validate_time_range(time_range_type, duration_in_mins, start_time, end_time)
        params.update({'metric-path': metric_path,
                       'rollup': rollup})

        return self._app_request(MetricData, '/metric-data', app_id, params)

    def get_events(self, app_id=None, event_types='ALL', severities='ERROR', time_range_type='BEFORE_NOW',
                   duration_in_mins=15, start_time=None, end_time=None):
        """
        Retrieves events.

        :param int app_id: Application ID to retrieve nodes for. If :const:`None`, the value stored in the
            `app_id` property will be used.
        :param str event_types: CSV of the events types to search on
        :param str severities: CSV of the severities to search on
        :param str time_range_type: Must be one of :const:`BEFORE_NOW`, :const:`BEFORE_TIME`,
            :const:`AFTER_TIME`, or :const:`BETWEEN_TIMES`.
            See :ref:`time-range-types` for a full explanation.
        :param int duration_in_mins: Number of minutes before now. Only valid if the
            :attr:`time_range_type` is :const:`BEFORE_NOW`.
        :param long start_time: Start time, expressed in milliseconds since epoch. Only valid if the
            :attr:`time_range_type` is :const:`AFTER_TIME` or :const:`BETWEEN_TIMES`.
        :param long end_time: End time, expressed in milliseconds since epoch. Only valid if the
            :attr:`time_range_type` is :const:`BEFORE_TIME` or :const:`BETWEEN_TIMES`.
        :param bool rollup: If :const:`False`, return individual data points for each time slice in
            the given time range. If :const:`True`, aggregates the data and returns a single data point.
        :returns: A list of events for the specified app, filtered by the event type and severities desired.
        :rtype: model.Events
        """

        params = self._validate_time_range(time_range_type, duration_in_mins, start_time, end_time)
        params.update({'event-types': event_types,
                       'severities': severities,
                       'output': 'JSON'})

        return self._app_request(Events, '/events', app_id, params)

    def create_event(self, app_id=None, summary='', comment='', eventtype='APPLICATION_CONFIG_CHANGE',
                     severity='INFO', customeventtype=None, node=None, tier=None, bt=None):
        """
        Creates an event.

        :param int app_id: Application ID to retrieve nodes for. If :const:`None`, the value stored in the
            `app_id` property will be used.
        :param str summary: Summary of the event
        :param str comment: Comment about the event
        :param str eventtype: Event type
        :param str severity: Severity of event, one of INFO, WARN, ERROR
        :returns: Message containing the event ID if successful
        """

        # TODO: support array of properties

        params = {'summary': summary,
                  'comment': comment,
                  'eventtype': eventtype,
                  'severity': severity}

        if (eventtype == "CUSTOM"):
            params.update({'customeventtype': customeventtype,
                           'node': node,
                           'tier': tier,
                           'bt': bt})

        path = self._app_path(app_id, '/events')
        return self.request(path, params, method='POST', query=True, use_json=False)

    def exclude_bt_list(self, app_id, bts=[], exclude=True):
        xml = '<business-transactions>'

        for bt_id in bts:
            xml = xml + '<business-transaction>'
            xml = xml + '<id>{0}</id>'.format(bt_id)
            xml = xml + '</business-transaction>'

        xml = xml + '</business-transactions>'

        params = {}
        if (exclude):
            params.update({'exclude': 'true'})
        else:
            params.update({'exclude': 'false'})

        path = self._app_path(app_id, '/business-transactions')

        if not path.startswith('/'):
            path = '/' + path
        url = self._base_url + path

        headers = {'Content-type': 'text/xml', 'Accept': 'text/plain'}
        r = self._get_session().request('POST', url, auth=self._auth, params=params, data=xml, headers=headers)

        return r

    def get_snapshots(self, app_id=None, time_range_type=None, duration_in_mins=None,
                      start_time=None, end_time=None, **kwargs):
        """
        Finds and returns any snapshots in the given time range that match a set of criteria. You must provide
        at least one condition to the search parameters in the :data:`kwargs` parameters. The list of valid
        conditions can be found `here <http://ws/2>`_.

        :param int app_id: Application ID to retrieve nodes for. If :const:`None`, the value stored in the
            `app_id` property will be used.
        :param str time_range_type: Must be one of :const:`BEFORE_NOW`, :const:`BEFORE_TIME`,
            :const:`AFTER_TIME`, or :const:`BETWEEN_TIMES`.
            See :ref:`time-range-types` for a full explanation.
        :param int duration_in_mins: Number of minutes before now. Only valid if the
            :attr:`time_range_type` is :const:`BEFORE_NOW`.
        :param long start_time: Start time, expressed in milliseconds since epoch. Only valid if the
            :attr:`time_range_type` is :const:`AFTER_TIME` or :const:`BETWEEN_TIMES`.
        :param long end_time: End time, expressed in milliseconds since epoch. Only valid if the
            :attr:`time_range_type` is :const:`BEFORE_TIME` or :const:`BETWEEN_TIMES`.
        :param kwargs: Additional key/value pairs to pass to the controller as search parameters.
        :returns: A list of snapshots.
        :rtype: model.Snapshots
        """

        self._validate_time_range(time_range_type, duration_in_mins, start_time, end_time)

        params = self._validate_time_range(time_range_type, duration_in_mins, start_time, end_time)

        for qs_name in self.SNAPSHOT_REQUEST_PARAMS:
            arg_name = qs_name.replace('-', '_')
            params[qs_name] = kwargs.get(arg_name, None)
            if qs_name in self.SNAPSHOT_REQUEST_LISTS and qs_name in kwargs:
                params[qs_name] = ','.join(params[qs_name])

        return self._app_request(Snapshots, '/request-snapshots', app_id, params)

    def get_policy_violations(self, app_id=None, time_range_type='BEFORE_NOW', duration_in_mins=15,
                              start_time=None, end_time=None):
        """
        Retrieves a list of policy violations during the specified time range.
        *NOTE:* Beginning with controller version 3.7, you should use :meth:`get_healthrule_violations` instead.

        :param int app_id: Application ID to retrieve nodes for. If :const:`None`, the value stored in the
            `app_id` property will be used.
        :param str time_range_type: Must be one of :const:`BEFORE_NOW`, :const:`BEFORE_TIME`,
            :const:`AFTER_TIME`, or :const:`BETWEEN_TIMES`.
            See :ref:`time-range-types` for a full explanation.
        :param int duration_in_mins: Number of minutes before now. Only valid if the
            :attr:`time_range_type` is :const:`BEFORE_NOW`.
        :param long start_time: Start time, expressed in milliseconds since epoch. Only valid if the
            :attr:`time_range_type` is :const:`AFTER_TIME` or :const:`BETWEEN_TIMES`.
        :param long end_time: End time, expressed in milliseconds since epoch. Only valid if the
            :attr:`time_range_type` is :const:`BEFORE_TIME` or :const:`BETWEEN_TIMES`.
        :returns: A list of policy violations.
        :rtype: model.PolicyViolations
        """

        params = self._validate_time_range(time_range_type, duration_in_mins, start_time, end_time)

        return self._app_request(PolicyViolations, '/problems/policy-violations', app_id, params)

    def get_healthrule_violations(self, app_id=None, time_range_type='BEFORE_NOW', duration_in_mins=15,
                                  start_time=None, end_time=None):
        """
        Retrieves a list of health rule violations during the specified time range. Compatible with
        controller version 3.7 and later.

        :param int app_id: Application ID to retrieve nodes for. If :const:`None`, the value stored in the
            `app_id` property will be used.
        :param str time_range_type: Must be one of :const:`BEFORE_NOW`, :const:`BEFORE_TIME`,
            :const:`AFTER_TIME`, or :const:`BETWEEN_TIMES`.
            See :ref:`time-range-types` for a full explanation.
        :param int duration_in_mins: Number of minutes before now. Only valid if the
            :attr:`time_range_type` is :const:`BEFORE_NOW`.
        :param long start_time: Start time, expressed in milliseconds since epoch. Only valid if the
            :attr:`time_range_type` is :const:`AFTER_TIME` or :const:`BETWEEN_TIMES`.
        :param long end_time: End time, expressed in milliseconds since epoch. Only valid if the
            :attr:`time_range_type` is :const:`BEFORE_TIME` or :const:`BETWEEN_TIMES`.
        :returns: A list of policy violations.
        :rtype: model.PolicyViolations
        """

        params = self._validate_time_range(time_range_type, duration_in_mins, start_time, end_time)

        return self._app_request(PolicyViolations, '/problems/healthrule-violations', app_id, params)

    def _v2_request(self, cls, path, params=None, method='GET'):
        return cls.from_json(self.request('/api' + path, params, method))

    def get_my_account(self):
        """
        :rtype: Account
        """
        return self._v2_request(Account, '/accounts/myaccount')

    def get_account(self, account_id):
        """
        :rtype: Account
        """
        return self._v2_request(Account, '/accounts/{0}'.format(account_id))

    def get_license_modules(self, account_id):
        """
        :rtype: LicenseModules
        """
        return self._v2_request(LicenseModules, '/accounts/{0}/licensemodules'.format(account_id))

    def set_metric_retention(self, account_id, days, app_id=None):
        path = '/controller/api/accounts/{0}/'.format(account_id)

        if (app_id):
            path = path + 'applications/{0}/'.format(app_id)

        path = path + 'metricstaleduration/{0}'.format(days)

        return self.request(path, method="POST", use_json=False)

    def get_action_suppressions(self, account_id, app_id):
        return self._v2_request(ActionSuppressionsResponse,
                                '/accounts/{0}/applications/{1}/actionsuppressions'.format(account_id, app_id))

    def get_action_suppression(self, account_id, app_id, action_suppression_id):
        return self._v2_request(ActionSuppression,
                                '/accounts/{0}/applications/{1}/actionsuppressions/{2}'.format(account_id,
                                                                                               app_id,
                                                                                               action_suppression_id))

    def delete_action_suppression(self, account_id, app_id, action_suppression_id):
        return self.request('/api/accounts/{0}/applications/{1}/actionsuppressions/{2}'.format(account_id,
                                                                                               app_id,
                                                                                               action_suppression_id),
                            method="DELETE",
                            use_json=False)

    def create_action_suppression(self, account_id, app_id, params):
        return self.request('/api/accounts/{0}/applications/{1}/actionsuppressions'.format(account_id, app_id),
                            method="POST",
                            use_json=False,
                            query=False,
                            params=params,
                            headers={'Content-Type': 'application/vnd.appd.cntrl+json;v=1'})

    def get_license_usage(self, account_id, license_module=None, start_time=None, end_time=None):
        """
        :param int account_id:
        :param str license_module:
        :param datetime.datetime start_time:
        :param datetime.datetime end_time:
        :rtype: HourlyLicenseUsages
        """
        if isinstance(start_time, datetime):
            start_time = start_time.isoformat()
        if isinstance(end_time, datetime):
            end_time = end_time.isoformat()

        params = {
            'licensemodule': license_module,
            'showfiveminutesresolution': 'False',
            'startdate': start_time,
            'enddate': end_time
        }
        return self._v2_request(HourlyLicenseUsages, '/accounts/{0}/licensemodules/usages'.format(account_id), params)

    def get_license_usage_5min(self, account_id, license_module=None, start_time=None, end_time=None):
        """
        :param int account_id:
        :param str license_module:
        :param datetime.datetime start_time:
        :param datetime.datetime end_time:
        :rtype: LicenseUsages
        """
        params = {
            'licensemodule': license_module,
            'showfiveminutesresolution': 'True',
            'startdate': start_time.isoformat() if start_time else None,
            'enddate': end_time.isoformat() if end_time else None
        }
        return self._v2_request(LicenseUsages, '/accounts/{0}/licensemodules/usages'.format(account_id), params)
