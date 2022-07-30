import nxlog


def pre_process(data):

    msg = data.get_field('raw_event')
    fields = msg.split(" ")
    pairs = {val.split("=")[0]: val.split("=")[1] for val in fields if val}
    data.set_field('type', pairs['type'])


def post_process(data):
    module = data.module
    if not 'counter' in module:
        module['counter'] = 0

    with open('tmp/processed', 'a') as file:
        if data.get_field('type') == 'CWD':
            module['counter'] += 1
            string = "{} {}\n".format(
                module['counter'],
                data.get_field('raw_event')
            )
            file.write(string)
    data.set_field('raw_event', data.get_field('raw_event'))


def bad_process1(data):
    data.post()

def bad_process2(data):
    data.module.logdata_new()

def bad_process3(data):
    data.module.set_read_timer(1)
