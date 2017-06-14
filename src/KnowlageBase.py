class TenantKnowlageBase(object):
    def __init__(self, flowtables: [] = list(), mac_addresses: [] = list()) -> None:
        super().__init__()
        self._allowed_flowtables = flowtables
        self._mac_addresses = mac_addresses

    def check_flowtable(self, flowtable) -> bool:
        return flowtable in self._allowed_flowtables

    def check_mac_address(self, mac_address) -> bool:
        return mac_address in self._mac_addresses

class KnowlageBase(object):
    def __init__(self) -> None:
        super().__init__()
        self._tenants = dict()

    def add_tenant(self, tenant_id, tenant_knowlage: TenantKnowlageBase):
        if not tenant_knowlage:
            raise ValueError("tenant_knowlage can't be None")
        self._tenants[tenant_id] = tenant_knowlage

    def get_tenant(self, tenant_id) -> TenantKnowlageBase:
        return self._tenants[tenant_id]

    def check_flowtable(self, tenant_id, flowtable):
        return self.get_tenant(tenant_id).check_flowtable(flowtable)

    def check_mac_address(self, tenant_id, mac_address):
        return self.get_tenant(tenant_id).check_mac_address(mac_address)

