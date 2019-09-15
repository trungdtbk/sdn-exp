#!/usr/bin/python

from ansible.module_utils._text import to_native
from ansible.errors import AnsibleError, AnsibleFilterError
class FilterModule(object):

    def filters(self):
        return {
                'format_interfaces': self.format_interfaces,
                'list_format': self.list_format,
                'make_networks_config': self.make_networks_config,
                'getattr': self.getattr,
                }

    def format_interfaces(self, interfaces, vlans):
        """take interfaces variable and return a list of ip addresses for router"""
        try:
            new_list = []
            for intf in interfaces:
                vid = vlans[intf['vlan']]['id']
                name = 'sdiro_net%s' % vid
                ip = '10.0.%s.253' % vid
                if 'ip' in intf:
                    ip = intf['ip']
                new_list.append({'name': name, 'ipv4_address': ip})
            return new_list
        except Exception as e:
            raise AnsibleFilterError('Error has occured: %s' % e)

    def make_networks_config(self, vlans, idx=1):
        networks_config = []
        for vlan in vlans:
            network_config = {}
            if type(vlan) == int:
                vid = vlan
                ip = '10.0.%d.%s' % (vid, idx)
            elif type(vlan) == dict:
                vid = vlan['vlan']
                ip = vlan.get('ip') or '10.0.%d.%s' % (vid, idx)
            networks_config.append({
                'name': 'sdiro_net%d' % vid,
                'ipv4_address': ip})
        return networks_config

    def getattr(self, a_dict, key, default=None):
        if key in a_dict:
            return a_dict[key]
        elif default is not None:
            return default
        return 'undefined'

    def list_format(self, a_list):
        """turn a list of ints into a list of items with format 'value:value'."""
        try:
            new_list = []
            for item in a_list:
                new_list.append('%s:%s' % (item, item))
            return new_list
        except Exception as e:
            raise AnsibleFilterError('Error occured when converting list: %s' % e)
