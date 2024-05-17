# This code emulates a benign attack with T1018 :Remote System Discovery. And the tatic: Discovery. 
# The type of attack code was found in: https://www.hhs.gov/sites/default/files/medusalocker-ransomware-analyst-note.pdf
# The script to emulate attack was found in: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md

$DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher("(ObjectCategory=Computer)")
$DirectorySearcher.PropertiesToLoad.Add("Name")
$Computers = $DirectorySearcher.findall()
foreach ($Computer in $Computers) {
  $Computer = $Computer.Properties.name
  if (!$Computer) { Continue }
  Write-Host $Computer}

  # Sysmon detection. Should run the script seperately on Powershell.
Get-WinEvent *Sysmon* | where message -like *T1018* | select -first 1 | Format-List