"""
Model classes for AppDynamics REST API

.. moduleauthor:: Todd Radel <tradel@appdynamics.com>
"""

from . import JsonObject, JsonList
from .entity_def import EntityDefinition


class Event(JsonObject):

    FIELDS = {'id': '',
              'summary': '',
              'type': '',
              'archived': '',
              'deep_link_url': 'deepLinkUrl',
              'event_time_ms': 'eventTime',
              'is_read': 'markedAsRead',
              'is_resolved': 'markedAsResolved',
              'severity': '',
              'sub_type': 'subType'}

    """
    https://docs.appdynamics.com/display/PRO42/Events+Reference
    """
    EVENT_TYPES = (
        'ACTIVITY_TRACE',
        'ADJUDICATION_CANCELLED',
        'AGENT_ADD_BLACKLIST_REG_LIMIT_REACHED',
        'AGENT_ASYNC_ADD_REG_LIMIT_REACHED',
        'AGENT_CONFIGURATION_ERROR',
        'AGENT_DIAGNOSTICS',
        'AGENT_ERROR_ADD_REG_LIMIT_REACHED',
        'AGENT_EVENT',
        'AGENT_METRIC_BLACKLIST_REG_LIMIT_REACHED',
        'AGENT_METRIC_REG_LIMIT_REACHED',
        'AGENT_STATUS',
        'ALREADY_ADJUDICATED',
        'APPDYNAMICS_CONFIGURATION_WARNINGS',
        'APPDYNAMICS_DATA',
        'APPLICATION_CONFIG_CHANGE',
        'APPLICATION_DEPLOYMENT',
        'APPLICATION_ERROR',
        'APP_SERVER_RESTART',
        'AZURE_AUTO_SCALING',
        'BACKEND_DISCOVERED',
        'BT_DISCOVERED',
        'CONTROLLER_AGENT_VERSION_INCOMPATIBILITY',
        'CONTROLLER_ASYNC_ADD_REG_LIMIT_REACHED',
        'CONTROLLER_ERROR_ADD_REG_LIMIT_REACHED',
        'CONTROLLER_EVENT_UPLOAD_LIMIT_REACHED',
        'CONTROLLER_METRIC_REG_LIMIT_REACHED',
        'CONTROLLER_RSD_UPLOAD_LIMIT_REACHED',
        'CUSTOM',
        'CUSTOM_ACTION_END',
        'CUSTOM_ACTION_FAILED',
        'CUSTOM_ACTION_STARTED',
        'DEADLOCK',
        'DIAGNOSTIC_SESSION',
        'DISK_SPACE',
        'EMAIL_SENT',
        'EUM_CLOUD_BROWSER_EVENT',
        'HIGH_END_TO_END_LATENCY',
        'INFO_INSTRUMENTATION_VISIBILITY',
        'INTERNAL_UI_EVENT',
        'LICENSE',
        'LOW_HEAP_MEMORY',
        'MACHINE_DISCOVERED',
        'MEMORY',
        'MEMORY_LEAK',
        'MEMORY_LEAK_DIAGNOSTICS',
        'MOBILE_CRASH_IOS_EVENT',
        'MOBILE_CRASH_ANDROID_EVENT',
        'NODE_DISCOVERED',
        'NORMAL',
        'OBJECT_CONTENT_SUMMARY',
        'POLICY_CANCELED',
        'POLICY_CANCELED_CRITICAL',
        'POLICY_CANCELED_WARNING',
        'POLICY_CLOSE',
        'POLICY_CLOSE_CRITICAL',
        'POLICY_CLOSE_WARNING',
        'POLICY_CONTINUES',
        'POLICY_CONTINUES_CRITICAL',
        'POLICY_CONTINUES_WARNING',
        'POLICY_DOWNGRADED',
        'POLICY_OPEN',
        'POLICY_OPEN_CRITICAL',
        'POLICY_OPEN_WARNING',
        'POLICY_UPGRADED',
        'RESOURCE_POOL_LIMIT',
        'RUNBOOK_DIAGNOSTIC_SESSION_END',
        'RUNBOOK_DIAGNOSTIC_SESSION_FAILED',
        'RUNBOOK_DIAGNOSTIC_SESSION_STARTED',
        'RUN_LOCAL_SCRIPT_ACTION_END',
        'RUN_LOCAL_SCRIPT_ACTION_FAILED',
        'RUN_LOCAL_SCRIPT_ACTION_STARTED',
        'SERVICE_ENDPOINT_DISCOVERED',
        'SLOW',
        'SMS_SENT',
        'STALL',
        'STALLED',
        'SYSTEM_LOG'
        'THREAD_DUMP_ACTION_END',
        'THREAD_DUMP_ACTION_FAILED',
        'THREAD_DUMP_ACTION_STARTED',
        'TIER_DISCOVERED',
        'VERY_SLOW',
        'WORKFLOW_ACTION_END',
        'WORKFLOW_ACTION_FAILED',
        'WORKFLOW_ACTION_STARTED')

    def __init__(self, event_id=0, event_type='CUSTOM', sub_type='', summary='', archived=False, event_time_ms=0,
                 is_read=False, is_resolved=False, severity='INFO', deep_link_url='',
                 triggered_entity=None, affected_entities=None):
        self._event_type = None
        (self.id, self.type, self.sub_type, self.summary, self.archived, self.event_time_ms, self.is_read,
         self.is_resolved, self.severity, self.deep_link_url) = (event_id, event_type, sub_type, summary, archived,
                                                                 event_time_ms, is_read, is_resolved, severity,
                                                                 deep_link_url)
        self.triggered_entity = triggered_entity or EntityDefinition()
        self.affected_entities = affected_entities or []

    @property
    def event_type(self):
        """
        :return:
        """
        return self._event_type

    @event_type.setter
    def event_type(self, new_type):
        self._list_setter('_event_type', new_type, Event.EVENT_TYPES)


class Events(JsonList):

    def __init__(self, initial_list=None):
        super(Events, self).__init__(Event, initial_list)

    def __getitem__(self, i):
        """
        :rtype: Event
        """
        return self.data[i]
