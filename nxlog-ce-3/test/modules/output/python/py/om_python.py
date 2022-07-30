import nxlog


def write_data1(logline):
    with open('tmp/output', 'a') as file:
        file.write(logline.get_field('raw_event') + "\n")


nxlog.log_info("INIT SCRIPT")
