from ofsctl import db

from utils import get_logger

logger = get_logger(__name__)


class TenantKnowledgeBase(object):
    def __init__(self, flowtables: [] = list(), mac_addresses: [] = list()) -> None:
        super().__init__()
        self._allowed_flowtables = flowtables
        self._mac_addresses = mac_addresses

    def check_flowtable(self, flowtable) -> bool:
        return flowtable in self._allowed_flowtables

    def check_mac_address(self, mac_address) -> bool:
        return mac_address in self._mac_addresses


class KnowledgeBase(object):
    def __init__(self) -> None:
        super().__init__()
        self._tenants = dict()

    def add_tenant(self, tenant_id, tenant_knowlage: TenantKnowledgeBase):
        if not tenant_knowlage:
            raise ValueError("tenant_knowledge can't be None")
        self._tenants[tenant_id] = tenant_knowlage

    def get_tenant(self, tenant_id) -> TenantKnowledgeBase:
        return self._tenants[tenant_id]

    def check_flowtable(self, tenant_id, flowtable) -> bool:
        if isinstance(flowtable, str):
            try:
                flowtable = int(flowtable, base=16)
            except ValueError:
                return False
        try:
            return self.get_tenant(tenant_id).check_flowtable(flowtable)
        except Exception as e:
            logger.error("check_flowtable(%s): %s" % (tenant_id, e))
            return False

    def check_mac_address(self, tenant_id, mac_address) -> bool:
        try:
            return self.get_tenant(tenant_id).check_mac_address(mac_address)
        except Exception:
            return False


class KnowledgeBaseOfsDb(KnowledgeBase):
    def __init__(self, ofsdb: db.ofs_db, of_tables_per_tenant=3) -> None:
        super().__init__()
        self._of_tables_per_tenant = of_tables_per_tenant
        self.ofsDb = ofsdb

    def check_flowtable(self, tenant_id, flowtable) -> bool:
        of_start_table = self.ofsDb.get_of_start_table_from_tenant(tenant_id)
        return flowtable in range(of_start_table, of_start_table + self._of_tables_per_tenant)
