import subprocess
import yara
import os
from datetime import datetime
import shutil
import argparse

# Create an ArgumentParser object
parser = argparse.ArgumentParser(description="YARA Web Shell scanner")

# Add arguments for directory and copy flag
parser.add_argument('-d', '--directory', required=True, help='Specify the directory to scan.')
parser.add_argument('-c', '--copy', action='store_true', help='Copy suspicious files if specified.')

# Parse the command-line arguments
args = parser.parse_args()

# Set the directory and copy flag based on parsed arguments
files_dir = args.directory
copy_if = args.copy

# Change the current working directory to './rules'
os.chdir('./rules')

yara_rules_file = 'main.yar'

yara_rules = yara.compile(yara_rules_file, error_on_warning=False)

print("Scanning at => " + files_dir)

# Get all file paths
command = ["find", files_dir, "-type", "f"]
cmd_output = subprocess.check_output(command, text=True)

scan_file_list = cmd_output.splitlines()

destination_dir = './clone'
# Initialize a list to store the results
results = []
os.chdir('..')
for scan_filepath in scan_file_list:
    matches = yara_rules.match(scan_filepath)
    if len(matches) > 0:
        result = {
            'File': scan_filepath,
            'Status': 'Suspicious',
            'Matches': ', '.join(str(match) for match in matches)
        }
        results.append(result)
        if copy_if:
            shutil.copy2(scan_filepath, os.path.join(destination_dir, os.path.basename(scan_filepath)+'.txt'))

# Generate HTML table if there are any suspicious files
os.chdir('./results')
if results:
    heading = """
    <pre>
 __          __  _        _____ _          _ _    _____                                 
 \ \        / / | |      / ____| |        | | |  / ____|                                
  \ \  /\  / /__| |__   | (___ | |__   ___| | | | (___   ___ __ _ _ __  _ __   ___ _ __ 
   \ \/  \/ / _ \ '_ \   \___ \| '_ \ / _ \ | |  \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
    \  /\  /  __/ |_) |  ____) | | | |  __/ | |  ____) | (_| (_| | | | | | | |  __/ |   
     \/  \/ \___|_.__/  |_____/|_| |_|\___|_|_| |_____/ \___\__,_|_| |_|_| |_|\___|_|   
                                                                          by mahmud0x              
                                                                                        
    </pre>
    """                                                                                       
    html_table = """
    <table border="1">
      <tr>
        <th>File</th>
        <th>Status</th>
        <th>Matches</th>
      </tr>
    """

    for result in results:
        html_table += f"""
      <tr>
        <td>{result['File']}</td>
        <td>{result['Status']}</td>
        <td>{result['Matches']}</td>
      </tr>
    """

    html_table += "</table>"

    # Save the HTML table to a file
    with open('scan_results_'+str(datetime.now().time())+'.html', 'w') as html_file:
        html_file.write(heading)
        html_file.write(html_table)
        
    print("HTML table saved as ./results/"+'scan_results_'+str(datetime.now().time())+'.html')
else:
    print("No suspicious files found.")

print("Done!")
