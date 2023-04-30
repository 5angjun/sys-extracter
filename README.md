# Sys-Extracter
This is the cross platform framework to recover driver's dispatch routine and all constraints for valid IOCTL codes.

It based on [IREC](https://github.com/kirasys/irec) and improve the IREC's limitations.

## Installation & Getting Start
```shell
# make virtual environment
pip uninstall virtualenv
pip install virtualenv
sudo apt install python3-virtualenv -y

virtualenv sangjun
source sangjun/bin/activate

pip install angr

python3 sys-extracter.py -driver target_driver.sys
```

## Example Result
Dispatch Routine
![](/screenshots/result1.png)   

Recovered IOCTL Constraints
![](/screenshots/result1.png)  
![](/screenshots/result2.png)  

## Implements of IREC
### Recovering IOCTL as well as other dispatch routine
![](/screenshots/DriverEntry.png) 

### Fix the finding method of Recovering OutputBufferLength & InputBufferLength Constraints
When OutputBufferLength < 8, it is invalid constraints but IREC have mistake analyze it.
![](/screenshots/Implements1.png) 


Sys-Extracter
```shell
    {   'InBufferLength': ['0-inf'],
        'IoControlCode': '0x7405c',
        'OutBufferLength': ['8-inf']},
```

IREC
```shell
  {   'InBufferLength': ['0-inf'],
        'IoControlCode': '0x7405c',
        'OutBufferLength': ['0-7']},
```

I fix this issue, so it can discover untainted code blocks.


IREC find the ended first Simstate and consider it is invalid constraints. But that has a error when All Simstate end same level.

So My Finder check IRP.IoStatus.Status fields and consider invalid constraints based on the [NT_STATUS Code](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-ntstatus-values)
```
NT_SUCCESS(Status)
Evaluates to TRUE if the return value specified by Status is a success type (0 − 0x3FFFFFFF) or an informational type (0x40000000 − 0x7FFFFFFF).

NT_INFORMATION(Status)
Evaluates to TRUE if the return value specified by Status is an informational type (0x40000000 − 0x7FFFFFFF).

NT_WARNING(Status)
Evaluates to TRUE if the return value specified by Status is a warning type (0x80000000 − 0xBFFFFFFF).

NT_ERROR(Status)
Evaluates to TRUE if the return value specified by Status is an error type (0xC0000000 - 0xFFFFFFFF).
```
