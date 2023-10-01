import os
import subprocess
from datetime import datetime
os.chdir('./rules')
yar_cmd = ["ls", "-1"]
yar_cmd_output = subprocess.check_output(yar_cmd, text=True).splitlines()
if os.path.exists('main.yar'):
    yar_cmd_output.remove('main.yar')
    os.rename('main.yar','.main.yar_'+str(datetime.now().time()))
with open('main.yar','a') as file:
    for yara_files in yar_cmd_output:
        file.write('include "'+yara_files+'"\n')
print("Rules setup done")
