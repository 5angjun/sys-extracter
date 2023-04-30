import angr
import archinfo
import mmap
import traceback

from . import structures
from . import explore_technique
"""
1. angr.Project 정의
2. angr.Project.factory 정의
3. angr.Project.factory에서 
"""
from typing import Final



STATUS_SUCCESS               : Final = 0
STATUS_UNSUCCESSFUL          : Final = 0xC0000001
STATUS_NOT_IMPLEMENTED       : Final = 0xc0000002
STATUS_INVALID_HANDLE        : Final = 0xc0000008
STATUS_INVALID_PARAMETER     : Final = 0xc000000d
STATUS_NOT_SUPPORTED         : Final = 0xc00000bb


pDrvObj_addr : Final     = 0xBEEF0000# 이걸 주소 0으로 할당하면 왜인지는 모르겠는데 Dispatch 복구가 안됐음
pRegPath : Final         = 0xBEEF1000
pIRP_addr : Final        = 0xBEEF2000
pIoStackLocation : Final = 0xBEEF3000
pDeviceObject_addr : Final = 0xBEEF4000
IRP_MJ_DEVICE_CONTROL : Final = 14# MajorFunction[14]=IRP_MJ_DEVICE_CONTROL;
need_to_swap = False
# https://docs.angr.io/en/latest/_modules/angr/factory.html

def speculate_bvs_range(state, bvs):
    """
    Speculate a range of the symbolic variable.
    """
    inf = 0xffffffff
    minv = state.solver.min(bvs)
    maxv = state.solver.max(bvs)
    
    if maxv == inf:  # when the max is infinite
        yield '%d-inf' % minv
        return
    
    i = start = minv
    while i <= maxv + 1:
        if not state.solver.satisfiable([bvs == i]):
            yield '%d-%d' % (start, i - 1)

            # find next start
            while not state.solver.satisfiable([bvs == i]) and i <= maxv + 1:
                i += 1
            start = i
        i += 1
        
class ExtractorFactory(angr.factory.AngrObjectFactory):

    def __init__(self, project):
        super(ExtractorFactory, self).__init__(project)
        # print(type(project.arch)) 윈도우 바이너리 돌려본 결과 <class 'archinfo.arch_amd64.ArchAMD64'>
        # 하지만 디폴트로 AMD64Calling 컨벤션 따라서 Microsoft로 Call바꿔줘야함
        # --> AMD64와 MicrosoftAMD64랑 사용하는 레지스터가 다르기 떄문.

        # archinfo -> https://github.com/angr/archinfo/blob/master/archinfo/arch_amd64.py
        if isinstance(project.arch, archinfo.ArchAMD64):
            #result = angr.calling_conventions.DEFAULT_CC.get(project.arch.name)            
            self._default_cc = angr.calling_conventions.SimCCMicrosoftAMD64(project.arch)#DEFAULT_CC.get(project.arch.name, SimCCUnknown)
        else:
            raise Exception("Please give me a Windows Binary")
            # 그냥 SimCCMicrosoftAMD64랑 SimCCSystemVAMD64랑 무슨 차이일까 -> 사용하는 레지스터가 달라서 무조건 SimCCMicrosoft를 사용해야함.
            
    

    def call_state(self, addr, *args, **kwargs):
        # call_state에서 kwargs로 _default_cc를 넘겨주어야 사용하는 Microsoft calling conventiond을 사용함.
        kwargs['cc'] = self._default_cc

        return super(ExtractorFactory, self).call_state(addr, *args, **kwargs)



# https://docs.angr.io/en/stable/_modules/angr/project.html
class Extractor(angr.Project):
# -> angr.Project객체를 상속받음으로써 Extractor = self를 p = angr.Project()에서 p 객체처럼 쓸 수 있다.    
    def __init__(self,bin_path):
        
        self.driver_path = bin_path

        super(Extractor, self).__init__(bin_path)
        self.factory = ExtractorFactory(self)
        self.global_variables2 = []
        self.project = self.factory.project
        self.dispatchs = None

    def set_mode(self, mode, state,debug=False):
        if mode == 'force_skip_call':
            def force_skip_call(state):
                state.mem[state.regs.rip].uint8_t = 0xc3
                state.regs.rax = state.solver.BVS('ret', 64)

            state.inspect.b('call', action=force_skip_call)


        elif mode == 'symbolize_global_variables':
            self.global_variables = []

            def symbolize_global_variables(state):
                obj = self.project.loader.main_object
                mem_read_address = state.solver.eval(state.inspect.mem_read_address)
                section = obj.find_section_containing(mem_read_address)

                if mem_read_address not in self.global_variables and '.data' in str(section):
                    self.global_variables.append(mem_read_address)
                    setattr(state.mem[mem_read_address], 'uint64_t', state.solver.BVS('global_%x' % mem_read_address, 64))
            state.inspect.b('mem_read', condition=symbolize_global_variables)   



    def find_device_name(self):

        DOS_DEVICES = "\\DosDevices\\".encode('utf-16le')
        possible_names = set()

        with open(self.driver_path,'rb') as f:
            b = mmap.mmap(f.fileno(), 0, access= mmap.ACCESS_READ)

            cursor = 0

            while cursor < len(b):
                cursor = b.find(DOS_DEVICES, cursor)

                # cannot find DosDevices
                if cursor == -1:
                    break
                
                # utf-16le == 2bytes
                terminal = b.find(b"\x00\x00", cursor)

                # padding
                if (terminal-cursor)%2:
                    terminal +=1
                
                result = b[cursor:terminal].decode('utf-16le')
                possible_names.add(result)
                cursor += len(result)
        
        # free mmap memory
        b.close()
        return possible_names
    

    def find_dispatchRoutine(self):
        #https://github.com/tpn/winsdk-10/blob/master/Include/10.0.14393.0/km/wdm.h


        init_state = self.factory.call_state(self.entry, pDrvObj_addr, pRegPath)

        pDrvObj = structures.DRIVER_OBJECT(init_state, pDrvObj_addr)
        simgr = self.factory.simgr(init_state)

        dispatch_list = []

        def set_major_functions(state):
            dispatch_addr = state.solver.eval(state.inspect.mem_write_expr)
            major_function_name = pDrvObj.get_name_from_addr(addr = state.solver.eval(state.inspect.mem_write_address))
            dispatch_list.append([major_function_name, dispatch_addr])

        for function_name in pDrvObj.get_MajorFunction():

            mj_function_offset = pDrvObj.get_offset(function_name)
            init_state.inspect.b('mem_write', when=angr.BP_AFTER, 
                             mem_write_address = pDrvObj.address + mj_function_offset,
                             action = set_major_functions)


        simgr.use_technique(angr.exploration_techniques.DFS())

        simgr.run(n=100)
        self.dispatchs = dict(dispatch_list)
        return self.dispatchs 
    

    def recovery_ioctl_interface(self):
        state = self.project.factory.call_state(self.dispatchs['IRP_MJ_DEVICE_CONTROL'], pDrvObj_addr, pIRP_addr)

        simgr = self.project.factory.simgr(state)


 
        io_stack_location = structures.IO_STACK_LOCATION(state, pIoStackLocation)
        irp = structures.IRP(state, pIRP_addr)

        state.solver.add(irp.fields['Tail.Overlay.CurrentStackLocation'] == io_stack_location.address)
        state.solver.add(io_stack_location.fields['MajorFunction'] == 14)

        # Find all I/O control codes.

        state_finder = explore_technique.SwitchStateFinder(io_stack_location.fields['IoControlCode'])
        simgr.use_technique(state_finder)
        simgr.run()

        ioctl_interface = []

        switch_states = state_finder.get_states()
        for ioctl_code, case_state in switch_states.items():
            #print(hex(ioctl_code), case_state)
            #if ioctl_code != 0x24038: continue
            def get_constraint_states(st):
                self.set_mode('symbolize_global_variables', st)

                preconstraints = []
                for constraint in st.history.jump_guards:

                    if 'Buffer' in str(constraint):

                        preconstraints.append(str(constraint))

                simgr = self.project.factory.simgr(st)

                for _ in range(10):
                    simgr.step()

                    for state in simgr.active:
                        for constraint in state.history.jump_guards:

                            if 'BufferLength' in str(constraint) and \
                                str(constraint) not in preconstraints:
                                
                                yield state

         
            constraint_states = get_constraint_states(case_state)

            try:

                sat_state = next(constraint_states)
                unsat_state = next(constraint_states)

                # Determine which constraints are valid.
                self.set_mode('force_skip_call', sat_state)
                self.set_mode('force_skip_call', unsat_state)


                global need_to_swap
                need_to_swap = False

                simgr_sat = self.factory.simgr(sat_state)
                simgr_unsat = self.factory.simgr(unsat_state)

                
                def sat_state_bp(state):
                    ntstatus_value = state.solver.eval(state.inspect.mem_write_expr)
                    
                    if ntstatus_value > 0xBFFFFFFF: 
                        global need_to_swap
                        need_to_swap = True

                def unsat_state_bp(state):
                    ntstatus_value = state.solver.eval(state.inspect.mem_write_expr)
                    if ntstatus_value <= 0xBFFFFFFF: 
                        global need_to_swap
                        need_to_swap = True


                sat_state.inspect.b('mem_write', when=angr.BP_AFTER, 
                    mem_write_address = irp.address + irp.get_offset('IoStatus.Status'),action = sat_state_bp)
                
                unsat_state.inspect.b('mem_write', when=angr.BP_AFTER, 
                    mem_write_address = irp.address + irp.get_offset('IoStatus.Status'),action = unsat_state_bp)
             
                
                for _ in range(15):
                    simgr_sat.step()

                for _ in range(15):   
                    simgr_unsat.step()


                if need_to_swap is True:
                    sat_state, unsat_state = unsat_state, sat_state


                # Get valid constraints.
                def get_valid_constraints(sat_state, unsat_state):
                    simgr = self.project.factory.simgr(sat_state)

                    for _ in range(10):
                        simgr.step()

                    if not simgr.stashes.values():
                        return
                    for states in list(simgr.stashes.values()):
                        for state in states:
                            ## DEBUG ##                   
                            # for addr in state.history.bbl_addrs: 
                            #     print(hex(addr))                            
                            # print("\n\n\n")
                            if unsat_state.addr not in state.history.bbl_addrs:
                                return state

                sat_state = get_valid_constraints(sat_state, unsat_state)
                if not sat_state:
                    sat_state = case_state # 

            except:
                sat_state = case_state
            finally:
                ioctl_interface.append({'IoControlCode': hex(ioctl_code), 
                                        'InBufferLength': list(speculate_bvs_range(sat_state, 
                                                                    io_stack_location.fields['InputBufferLength'])),
                                        'OutBufferLength': list(speculate_bvs_range(sat_state,
                                                                    io_stack_location.fields['OutputBufferLength'])
                                        )})
        return ioctl_interface
