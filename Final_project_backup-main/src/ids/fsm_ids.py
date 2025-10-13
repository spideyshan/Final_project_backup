# src/ids/fsm_ids.py
from transitions import Machine

class IDSModel:
    states = ['normal','suspicious','confirmed','alert']

    def __init__(self):
        self.machine = Machine(model=self, states=IDSModel.states, initial='normal')
        self.machine.add_transition('saw_suspicious', 'normal', 'suspicious')
        self.machine.add_transition('escalate', 'suspicious', 'confirmed')
        self.machine.add_transition('alert', 'confirmed', 'alert')
        self.machine.add_transition('reset', ['suspicious','confirmed','alert'], 'normal')
