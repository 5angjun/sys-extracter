import angr
import traceback
CONSTRAINT_MODE = 'constraints'
NtStatusFinalized = "ntstatusfinalized"



class SwitchStateFinder(angr.ExplorationTechnique):
    """
    An exploration technique to get all states of the switch-case statement.
    """
    def __init__(self, case):
        super(SwitchStateFinder, self).__init__()
        self._case = case
        self.switch_states = {} # io_control_code가 특정되는 State
        self.constraint_stashs = []

    def setup(self, simgr):
        simgr.populate(CONSTRAINT_MODE, []) # create the 'constraints' stash


    # 오버라이딩
    def step(self, simgr, stash='active', **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)

        if stash == 'active' and len(simgr.stashes[stash]) > 1:
            saved_states = [] 

            # active에 있는 분기문들을 전부 돌아봄
            for state in simgr.stashes[stash]:
                try:
                    # officail : 컨트롤 코드가 하나로 특정되면 그 경로는 더이상 탐색하지 않음.
                    # io_control_code 값을 가져와서 저장.
                    io_code = state.solver.eval_one(self._case)
                    if io_code in self.switch_states: # duplicated codes
                        continue
                    
                    # 해당 io_control_code값을 뽑아내는 분기문 저장
                    self.switch_states[io_code] = state
                except:
                    # err_msg = traceback.format_exc()
                    # print(err_msg)
                    saved_states.append(state)
            # active에 
            simgr.stashes[stash] = saved_states

        return simgr

    def get_states(self):
        return self.switch_states 
    
    