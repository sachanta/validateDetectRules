"""
Model classes for AppDynamics REST API

.. moduleauthor:: Kyle Furlong <kyle.furlong@appdynamics.com>
"""

from . import JsonObject, JsonList


class Backend(JsonObject):

    FIELDS = {'id': '', 'name': '', 'exit_point_type': 'exitPointType', 'properties': ''}
    EXIT_POINT_TYPES = ('HTTP', 'CACHE', 'DB', 'WEB_SERVICE', 'MODULE')

    def __init(self, backend_id=0, name='', exit_point_type='', properties=''):
        self._exit_point_type = None
        self.id, self.name, self.exit_point_type, self.properties, = \
            backend_id, name, exit_point_type, properties

    @property
    def exit_point_type(self):
        """
        :rtype: str
        """
        return self._exit_point_type

    @exit_point_type.setter
    def exit_point_type(self, exit_point_type):
        self._list_setter('_exit_point_type', exit_point_type, Backend.EXIT_POINT_TYPES)


class Backends(JsonList):

    def __init__(self, initial_list=None):
        super(Backends, self).__init__(Backend, initial_list)

    def __getitem__(self, i):
        """
        :rtype: Backend
        """
        return self.data[i]

    def by_exit_point_type(self, exit_point_type):
        """
        Searches for backends of a particular type (which should be one of Backend.EXIT_POINT_TYPES).
        For example, to find all the HTTP backends:

        >>> from appd.request import AppDynamicsClient
        >>> client = AppDynamicsClient(...)
        >>> all_backends = client.get_backends()
        >>> http_backends = all_backends.by_exit_point_type('HTTP')

        :returns: a Tiers object containing any tiers matching the criteria
        :rtype: Tiers
        """
        return Backends([x for x in self.data if x.exit_point_type == exit_point_type])
