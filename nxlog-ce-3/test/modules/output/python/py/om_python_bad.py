import nxlog

class Selector:
    def __init__(self):
        self.case = 0
    def run(self, logdata):
        self.case += 1
        if self.case == 1:
            logdata.post()
        elif self.case == 2:
            logdata.module.logdata_new()
        elif self.case == 3:
            logdata.module.set_read_timer(1)


def write_data(data):
    if not 'selector' in data.module:
        data.module['selector'] = Selector()

    data.module['selector'].run(data)
