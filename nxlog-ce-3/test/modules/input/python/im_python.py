import nxlog


class TestReader:

    def __init__(self):
        with open('modules/input/python/input.txt', 'r') as file:
            self.lines = file.readlines()
        nxlog.log_debug(str(len(self.lines)))

    def getnext(self):
        if not self.lines:
            return None
        line = self.lines.pop(0)
        return line.rstrip()


def read_data1(module):

    if not 'reader' in module:
        module['reader'] = TestReader()
    reader = module['reader']
    logdata = module.logdata_new()
    line = reader.getnext()

    if not line:
        nxlog.log_info("EOF")
        return

    logdata.set_field('raw_event', line)

    logdata.post()
    module.set_read_timer(0.005)

nxlog.log_debug("INIT SCRIPT")
