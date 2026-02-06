from dataclasses import dataclass
from typing import Optional

from .models import BusinessElement, AccessRoleRule


@dataclass(frozen=True)
class CanResult:
    allowed: bool
    status_code: int   # 200, 401, 403
    reason: str
    


def _user_pk(user) -> Optional[int]:
    # your user primary key is user_id
    return getattr(user, "user_id", None)


def can(user, element_code: str, action: str, owner_id: Optional[int] = None) -> CanResult:
    """
    Rules:
      - 401 if user is not identified or inactive
      - 403 if identified but forbidden
      - if *_all_permission is True -> allow regardless of owner
      - else if *_permission is True -> allow only when owner_id == user.user_id
      - create ignores owner_id (because object doesn't exist yet)
    """

    # 1) Authentication check
    if not user or not getattr(user, "is_active", False):
        return CanResult(False, 401, "unauthorized")

    # 2) Role must exist
    role = getattr(user, "role", None)
    if not role:
        return CanResult(False, 403, "no_role_assigned")

    # 3) Validate action
    action = (action or "").strip().lower()
    if action not in {"read", "create", "update", "delete"}:
        return CanResult(False, 403, "invalid_action")

    # 4) Get element
    element = BusinessElement.objects.filter(code=element_code).first()
    if not element:
        return CanResult(False, 403, "unknown_resource")

    # 5) Get rule
    rule = AccessRoleRule.objects.filter(role=role, element=element).first()
    if not rule:
        return CanResult(False, 403, "no_rule_defined")

    uid = _user_pk(user)

    def is_owner() -> bool:
        return owner_id is not None and uid is not None and owner_id == uid

    # 6) Decision logic
    if action == "create":
        return CanResult(bool(rule.create_permission), 200 if rule.create_permission else 403,
                         "create_allowed" if rule.create_permission else "create_forbidden")

    if action == "read":
        if rule.read_all_permission:
            return CanResult(True, 200, "read_all_allowed")
        if rule.read_permission and is_owner():
            return CanResult(True, 200, "read_own_allowed")
        return CanResult(False, 403, "read_forbidden")

    if action == "update":
        if rule.update_all_permission:
            return CanResult(True, 200, "update_all_allowed")
        if rule.update_permission and is_owner():
            return CanResult(True, 200, "update_own_allowed")
        return CanResult(False, 403, "update_forbidden")

    if action == "delete":
        if rule.delete_all_permission:
            return CanResult(True, 200, "delete_all_allowed")
        if rule.delete_permission and is_owner():
            return CanResult(True, 200, "delete_own_allowed")
        return CanResult(False, 403, "delete_forbidden")

    

    return CanResult(False, 403, "forbidden")
