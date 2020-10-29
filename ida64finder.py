import idc
import idaapi
import ida_funcs

def define_func(name, addr):
  ida_funcs.add_func(addr)

  print("[iBoot64Finder]: %s = %x" % (name, addr))

  idc.set_name(addr, name, idc.SN_CHECK)

def i64f(ibotlog):
  with open(ibotlog, "r") as ibot:
    for line in ibot.readlines():
      if "=" in line:
        func = line.split()[1]

        if func == "base_addr": func = "_start"

        addr = int(line.split()[3], 0)

        define_func(func, addr)