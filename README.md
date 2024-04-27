# DNS / DHCP Network Capture Parser

This is a project to parse network capture files and extract DNS and DHCP information.

## Running The Program

Download the program `dns-dhcp-parser`

```sh
dns-dhcp-parser ./hex-dump-file.txt
```

Then select what you want to do (print to console or output to file).

```txt
How do you want to output the data?
1. Print to console
2. Save to file
```

Print to console will print the parsed data to the console.
Save to file will output the parsed data to a yaml file.

## Compiling on Your Machine

To activate virtual env, run following command

```sh
python -m venv env # Create a new virtual environment (replace 'env' with your desired environment name)
source env/bin/activate # MacOS / Linux
.\env\Scripts\activate # Windows
```

Install the required packages

```sh
pip install -r requirements.txt
```

Run the program with

```sh
python ./src ./hex-dump-file.txt
```

Compile the program with

```sh
pyinstaller --onefile -n dns-dhcp-parser ./src/main.py
```
