#  irec.py
#  sys-extracter.py  
#
#  Copyright 2020 Namjun Jo <kirasys@theori.io>
#  Copyright 2023 Sangjun Park <best_collin@naver.com>
#
#  Redistribution and use in source and binary forms, with or without modification,
#  are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright notice,
#      this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#    * Neither the name of {{ project }} nor the names of its contributors
#      may be used to endorse or promote products derived from this software
#      without specific prior written permission.
# 
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
#  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
#  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
#  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
#  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
#  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
#  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.



import argparse
import os
import pprint
import logging
''' refs : https://gist.github.com/brantfaircloth/1252339/0dc4018ffa01ac805a0c799097114af86867ab37 '''
class FullPaths(argparse.Action):
    """Expand user- and relative-paths"""
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, os.path.abspath(os.path.expanduser(values)))

''' refs : https://stackoverflow.com/questions/11540854/file-as-command-line-argument-for-argparse-error-message-if-argument-is-not-va '''
def is_valid_file(parser, path):
    if not os.path.exists(path):
        parser.error("The file %s does not exist!" % path)
    else:
        return path  # return an open file handle


def setupLogging():
    logging.getLogger('angr').setLevel("FATAL")


def get_args():
    parser = argparse.ArgumentParser(description='Something smart here')
    parser.add_argument('-driver', metavar='<Driver Path>', required=True,action = FullPaths,
                    help='Locate driver path',type=lambda x: is_valid_file(parser, x))
    return parser.parse_args()



if __name__=="__main__":
    parser = get_args()
    print(f"Target Driver path is {parser.driver}\n")

    setupLogging()
    from common import core
    print("Constructing Angr Objects\n")
    driver_object = core.Extractor(parser.driver)

    
    print("Finding Device Driver Symbolic Link...")
    Symbolic_link = driver_object.find_device_name()
    print(f"possible Symbolic Link is {Symbolic_link}\n")


    print("Finding valid Dispatch Routine")
    dispatchers = driver_object.find_dispatchRoutine()
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(dispatchers)
    print("\n\n")
    if "IRP_MJ_DEVICE_CONTROL" in dispatchers:
        print("IOCTL Code Recovering...")
        ioctl_interface = driver_object.recovery_ioctl_interface()

        print("\t> IOCTL Interface :")
        
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(ioctl_interface)


    print("DONE")
