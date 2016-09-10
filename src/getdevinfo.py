#!/usr/bin/env python

import subprocess
import shlex


IB_INFO = {"max_qp:": "MAX_QPS",
           "max_qp_wr:": "MAX_WRS",
           "max_sge:": "MAX_SGES",
           "max_mr:": "MAX_MRS"}

IB_NUMS = {}
CONST_WRS = 512

HEADER = """#ifndef __CONFIG_H_
#define __CONFIG_H_\n
/* This is an autogenerated file! */\n"""

FOOTER = """\n#endif /* __CONFIG_H_ */"""


def run_cmd(args):
    args = shlex.split(args)
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=None)
    return p.communicate()[0]


def main():
    num_cores = int(run_cmd("grep -c processor /proc/cpuinfo"))
    ibv_output = run_cmd("ibv_devinfo -vvv").split('\n')
    for i in ibv_output:
        for key in IB_INFO:
            if key in i:
                a = [int(s) for s in i.split('\t') if s.isdigit()][0]
                IB_NUMS.update({IB_INFO[key]: a})
    const_wrs = CONST_WRS
    if const_wrs <= num_cores:
        const_wrs = 2 * num_cores
    per_core_recv_wrs = const_wrs / num_cores
    per_core_persist_wrs = const_wrs / num_cores
    total_recv_wrs = num_cores * per_core_recv_wrs
    total_persist_wrs = num_cores * per_core_persist_wrs
    per_core_flush_wrs = (IB_NUMS["MAX_WRS"] -
                          (total_recv_wrs + total_persist_wrs)) / num_cores
    total_flush_wrs = per_core_flush_wrs * num_cores
    IB_NUMS.update({"TOTAL_FLUSH_WRS": total_flush_wrs})
    IB_NUMS.update({"TOTAL_PERSIST_WRS": total_persist_wrs})
    IB_NUMS.update({"TOTAL_RECV_WRS": total_recv_wrs})
    IB_NUMS.update({"PER_CORE_FLUSH_WRS": per_core_flush_wrs})
    IB_NUMS.update({"PER_CORE_PERSIST_WRS": per_core_persist_wrs})
    IB_NUMS.update({"PER_CORE_RECV_WRS": per_core_recv_wrs})
    IB_NUMS.update({"ONLINE_CORES": num_cores})

    print HEADER
    for key, value in IB_NUMS.iteritems():
        print "#define %s %d" % (key, value)

    print ''
    with open('CONF', 'r') as f:
        content = f.readlines()
        for i in content:
            v = i.split('=')
            print "#define %s \"%s\"" % (v[0].strip(' '),
                                         v[1].strip('\n').strip(' '))
    print FOOTER
    file.close

if __name__ == '__main__':
    main()
