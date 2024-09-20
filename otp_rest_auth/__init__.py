VERSION = (0, 1, 8, "final", 0)

__title__ = "otp-rest-auth"
__version_info__ = VERSION
__version__ = ".".join(map(str, VERSION[:3])) + (
    "-{}{}".format(VERSION[3], VERSION[4] or "") if VERSION[3] != "final" else ""
)
__author__ = "Leptons Multiconcept"
__license__ = "MIT"
__copyright__ = "Copyright (c) 2024 Leptons-Multiconcept"
