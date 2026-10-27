"""Read redirected Downloads for loaded Windows profiles, including services."""
import os
import re
from pathlib import Path

def redirected_downloads():
    if os.name != 'nt':return []
    import winreg
    roots=[]
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList') as profiles:
            for i in range(winreg.QueryInfoKey(profiles)[0]):
                sid=winreg.EnumKey(profiles,i)
                try:
                    with winreg.OpenKey(profiles,sid) as profile:
                        profile_path=os.path.expandvars(winreg.QueryValueEx(profile,'ProfileImagePath')[0])
                    with winreg.OpenKey(winreg.HKEY_USERS,sid+r'\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders') as folders:
                        value=winreg.QueryValueEx(folders,'{374DE290-123F-4565-9164-39C4925E467B}')[0]
                    if not isinstance(value,str):continue
                    value=re.sub(r'%USERPROFILE%',lambda _:profile_path,value,flags=re.I)
                    # Do not substitute the service account's USERPROFILE or
                    # OneDrive into a different user's folder configuration.
                    if '%' in value:continue
                    path=Path(value)
                    if path.is_absolute() and path.is_dir() and not path.is_symlink() and not path.is_junction():roots.append(path)
                except OSError:
                    continue  # Unloaded/inaccessible profile; default local paths remain.
    except OSError:
        return []
    return list(dict.fromkeys(roots))
