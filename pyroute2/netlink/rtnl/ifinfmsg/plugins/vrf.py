from pyroute2.netlink import nla


class vrf(nla):
    nla_map = (('IFLA_VRF_UNSPEC', 'none'),
               ('IFLA_VRF_TABLE', 'uint32'))
