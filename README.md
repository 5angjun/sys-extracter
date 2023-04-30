# Sys-Extracter
This is the cross platform framework to recover driver's dispatch routine and all constraints for valid IOCTL codes.

It based on [IREC] (https://github.com/kirasys/irec) and improve the IREC's limitations.

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


Recovered IOCTL Constraints


## Implements of IREC
### Recovering IOCTL as well as other dispatch routine


### Fix the finding method of Recovering OutBufferLength & InputBufferLength Constraints
-> 