# -*- coding: utf-8 -*-
"""
collector/__init__.py
Cross-platform dispatch: automatically selects Windows or Linux collector
based on the current runtime environment.
"""
import platform as _platform

from collector.base import get_local_ip_address, get_system_info  # noqa: F401

_IS_WINDOWS = _platform.system() == "Windows"

if _IS_WINDOWS:
    from collector.windows import (  # noqa: F401
        get_defender_info,
        get_installed_updates,
        get_installed_programs,
        get_local_user_accounts,
        get_password_policy,
        get_network_settings,
        get_os_info,
    )
else:
    from collector.linux import (  # noqa: F401
        get_defender_info,
        get_installed_updates,
        get_installed_programs,
        get_local_user_accounts,
        get_password_policy,
        get_network_settings,
        get_os_info,
    )
