# file_list = ["Td4"]
file_list = ["Te0", "Te1", "Te2", "Te3", "Te4", "Td0", "Td1", "Td2", "Td3", "Td4", "rcon"]
# wr_file_list = ["Te0_c", "Te1_c", "Te2_c", "Te3_c", "Te4_c", "Td0_c", "Td1_c", "Td2_c", "Td3_c", "Td4_c", "rcon_c"]

code = ""
for x in file_list:
  size = 256
  index = 0
  if x[0] == 'r':
    size = 10
  rx = x + ".txt"
  wx = x + "_c" + ".txt"
  rf = open(rx, "r")
  wf = open(wx, "w")
  buf = rf.read()
  buf_l = buf.splitlines()
  code_line = x + " = malloc(sizeof(uint32_t) * " + str(size) + ")" + "\n"
  wf.write(code_line)
  for l in buf_l:
    num_list_line = l.split(',')
    for nl in num_list_line:
      if len(nl) > 0:
        num = nl.strip()
        code_line = x + "[" + str(index) + "]" + " = " + num + ";\n"
        index = index + 1
        wf.write(code_line)
  wf.close()
  rf.close()


  