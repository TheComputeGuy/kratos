# Kratos

This tool builds on top of [Jedi](https://github.com/TheComputeGuy/Jedi), a fork of [Cyber Forensics Innovation Lab's](https://cyfi.ece.gatech.edu/) [Yoda](https://github.com/CyFI-Lab-Public/YODA), a tool to analyse website backups for malicious plugins delivered via well-known Content Management Systems.

Jedi aims to run analysis on non-plugin files to perform the same, and also aims to add more analysis rules to improve the web malware detection capabilities of Yoda.

## Installing

This app best works in Linux, running it in Windows requires certain quirks especially regarding the PHP runtime and how the phar files are executed.

Start by cloning this repo

### [Optional - Recommended] Using a virtual environment

Install and setup virtual environment

```
pip install virtualenv
virtualenv venv
```

To activate your virtualenv

```
source ./venv/bin/activate
```

To exit the virtual environment

```
deactivate
```

### App setup

Install the required dependencies

```
pip install -r requirements.txt
```

Other requirements include having a PHP runtime and having the php-dev packages installed.

### PHP library setup

You will need to have installed php and php{x}-dev (x=your PHP runtime version) in your machine  
The script ```ast-setup.sh``` will help you in setting up the nikic/php-ast library  
[Composer](https://getcomposer.org/) is used as the package manager for PHP libraries  
To complete the setup of all PHP libraries, run the script ```ast_vendor_setup.sh``` in the ast_utils directory.  

## Running locally

```
python framework.py <path to downloaded plugin folder>
```

## Running as a container (using Docker)

### Note

When running as a container, the plugin path is provided using the environment variable BASE_PATH (this is a MANDATORY environment variable since running Kratos as a container in current state cannot accept plugin path as an argument). If the plugins are a part of your bridge directory, BASE_PATH should be relative to mount path inside the container (```/usr/src/bridge/``` by default, as defined in the Dockerfile)  
Kratos has been modified to use a bridge directory with the host when running as a container (when the environment variable BRIDGE_DIR is available - has been hardcoded in the Dockerfile as of now), hence, it needs a volume mount to write the reports from the container. Modify the Dockerfile to remove this environment variable if this functionality is not needed.  

| Environment Variable | Purpose | Mandatory in container mode? |
| - | - | - |
| BASE_PATH | Path to the downloaded plugin | Yes |
| BRIDGE_DIR | Path to the mount destination of bridge directory volume in the container | No* |

\* Defined by default in the Dockerfile to be ```/usr/src/bridge/```

<br />

```
docker build -t kratos .
docker run --mount type=bind,src=$volume_src_dir,target='/usr/src/bridge' -e BASE_PATH=$base_path kratos
```


## Included scripts
1. [RAR Extractor](scripts/extractor_rar.py) - Recursively extracts all RAR files in a directory (also extracts ZIP files inside the RAR file when in recursive mode)
2. [ZIP Extractor](scripts/extractor.py) - Recursively extracts all ZIP files in a directory
3. [Run All](scripts/run_all.ps1) - A powershell script to run the framework on all plugins in a given folder as containers. Bash equivalent can be generated trivially easily.


## Note
1. This code has been tested in Python 3.8.10 and may not necessarily work in Python 3.10 and onwards owing to changes in some method signatures in Python 3.10.  
2. Kratos does not support writing results to AWS S3/Azure Blob Storage/GCP Object Storage/Cloudflare R2/Backblaze B2, but can be trivially modified to include this support using the boto SDK. AWS-specific implementation can be found in the Jedi code, and can be generalized to work for any cloud provider.  

---


## Relevant previous work from CyFI Lab
[TARDIS](https://ieeexplore.ieee.org/document/9152609)

R. Pai Kasturi et al., "TARDIS: Rolling Back The Clock On CMS-Targeting Cyber Attacks," 2020 IEEE Symposium on Security and Privacy (SP), 2020, pp. 1156-1171, doi: 10.1109/SP40000.2020.00116.
<br></br>
[YODA](https://www.usenix.org/conference/usenixsecurity22/presentation/kasturi)

‘Mistrust Plugins You Must: A Large-Scale Study Of Malicious Plugins In WordPress Marketplaces’, στο 31st USENIX Security Symposium (USENIX Security 22), 2022.
