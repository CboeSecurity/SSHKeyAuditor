import sys
from cx_Freeze import setup, Executable

setup(
    name = "OpenSSH Auditor",
    version = "0.1",
    description = "Audits a directory for potential instances of SSH private keys, reports if encrypted or unencrypted",
    executables = [Executable("AuditSSHKeys.py", base = "Win32GUI")])
