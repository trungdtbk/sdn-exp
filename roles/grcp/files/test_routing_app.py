import logging

from grcp.app_manager import AppBase
from grcp.app_manager import get_topo_manager
from grcp.app_manager import listen_to_ev
from grcp.core.topology import EventRouteAdd
from grcp.core.topology import EventPeerUp
from grcp.core.topology import EventLinkStatsChange
from grcp.core.model import Path

logger = logging.getLogger('testapp')

class TestRoutingApp(AppBase):

    def __init__(self):
        super(TestRoutingApp, self).__init__()
        self.topo = get_topo_manager()
        self.peer = None
        self.util_threshold = 0.4

    @listen_to_ev([EventLinkStatsChange])
    def handle_link_overload(self, ev):
        link = ev.msg
        if link.utilization > self.util_threshold:
            logger.info('link utilization exceeds threshold')

            qry = Path.query(routerid='10.0.10.1', prefix='1.2.2.0/24', for_peer=True)
            qry = qry.filter(Path.inter_util < 0.5)
            qry = qry.order(Path.inter_util, Path.inter_delay, -Path.inter_bw)
            path = qry.fetch(limit=1)
            if path:
                logger.info('path to be used: %s' % path)
                self.topo.create_mapping(routerid='10.0.10.1',
                                         prefix='1.2.2.0/24',
                                         path_info=path[0],
                                         for_peer=True)

    @listen_to_ev([EventPeerUp])
    def peer_up_handler(self, ev):
        peer = ev.msg
        if peer.peer_ip == '10.0.20.2':
            self.peer = peer
            logger.info('register a peer: %s' % peer)
