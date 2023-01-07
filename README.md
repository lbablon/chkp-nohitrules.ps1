
# chkp-nohitrules.ps1 - Powershell script to export access rules with 0 hit from a policy

The script uses Checkpoint webservices api to connect to a management server and export all access rules that never match (0 hit) from a specified access layer into a csv file. 

The script as been tested on R81.10 with api version 1.8.1 and above, but it should also works with older versions. No compatibility ith MDS yet. 

## Parameters

- **[-server]**, Checkpoint management server's ip address or fqdn.
- **[-user]**, user with sufficient permissions on the management server.
- **[-password]**, password for the api user.
- **[-accesslayer]**, access layer's name that corresponds to the policy package you want to export rules from.
- **[-fromdate]**,  only rules with no hit starting from this date will be listed. Format should be "dd/MM/yyyy"
- **[-path]**, filepath where you want to export the results. This should be a .csv file.

## Examples

```
"./chkp-nohitrules.ps1" -Server 192.168.1.50 -user admin -AccessLayer "Standard"
```

Runs the script then asks the user for password then and export all rules that never matched from the access layer named "Standard" then asks the user where to save the results as a csv file. 

```
"./chkp-nohitrules.ps1" -Server 192.168.1.50 -user admin -password Str0nK! -AccessLayer "Standard" -Path "C:\Temp\rules.csv"
```

Runs the script in non interactive mode and export the access rules to C:\Temp\rules.csv

```
"./chkp-nohitrules.ps1" -Server 192.168.1.50 -user admin -password Str0nK! -AccessLayer "Standard" -FromDate "22/11/2021" -Path "C:\Temp\rules.csv"
```

Runs the script an returns all rules that have not matched since the 22 nov. 2021
