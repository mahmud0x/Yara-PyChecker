import subprocess
import yara
import os

os.chdir('./rules')
yara_rules_file = 'main.yar' #Location of main.yar

yara_rules = yara.compile(yara_rules_file,error_on_warning = False)

#yara_rules_save = yara_rules.save('/home/mahmud/Desktop/php_test/rules/compiled')

#Input Dir
files_dir = input("Enter file directory: ")
print("Scanning at => " + files_dir)

#Get all file paths
command = ["find", files_dir, "-type", "f"]
cmd_output = subprocess.check_output(command, text=True)

scan_file_list = cmd_output.splitlines()

for scan_filepath in scan_file_list:
    matches = yara_rules.match(scan_filepath)
    if len(matches) > 0:
        print(scan_filepath, end="\n")
        print("Suspicious \n")
        print(matches)
print("Done!")

