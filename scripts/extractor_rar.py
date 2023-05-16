import patoolib
import argparse
import os
import zipfile
import re

def extract_nested_zip(zippedFile, toFolder):
    """ Extract a zip file including nested zip files
        Delete the zip file(s) after extraction
    """
    with zipfile.ZipFile(zippedFile, 'r') as zfile:
        zfile.extractall(path=toFolder)
    os.remove(zippedFile)
    for root, dirs, files in os.walk(toFolder):
        for filename in files:
            if filename.endswith('.rar'):
                fileSpec = os.path.join(root, filename)
                try:
                    extract_nested_rar(fileSpec, root)
                except Exception as e:
                    pass	
                    #print(f"Error extracting {fileSpec}: {e}")
            if re.search(r'\.zip$', filename):
                fileSpec = os.path.join(root, filename)
                try:
                    extract_nested_zip(fileSpec, root)
                except Exception as e:
                    pass	
                    #print(f"Error extracting {fileSpec}: {e}")

def extract_nested_rar(rarFile, toFolder):
    """ Extract a RAR file including nested RAR files
        Delete the RAR file(s) after extraction
    """
    patoolib.extract_archive(rarFile, outdir=toFolder)
    os.remove(rarFile)
    for root, dirs, files in os.walk(toFolder):
        for filename in files:
            if filename.endswith('.rar'):
                fileSpec = os.path.join(root, filename)
                try:
                    extract_nested_rar(fileSpec, root)
                except Exception as e:
                    pass	
                    #print(f"Error extracting {fileSpec}: {e}")
            if re.search(r'\.zip$', filename):
                fileSpec = os.path.join(root, filename)
                try:
                    extract_nested_zip(fileSpec, root)
                except Exception as e:
                    pass	
                    #print(f"Error extracting {fileSpec}: {e}")

# get a list of all the files in the current directory
parser = argparse.ArgumentParser()
parser.add_argument("base_path", help="The path of extraction")
args = parser.parse_args()
base_path = args.base_path
files_in_dir = os.listdir(base_path)

# filter for only the rar files
rar_files = [f for f in files_in_dir if f.endswith('.rar')]

# extract all the nested rar files
for rar_file in rar_files:
    current_dir = base_path
    rar_dir_name = rar_file.replace(".rar", "")
    current_dir=current_dir+"/"+rar_dir_name
    current_dir = current_dir.strip()
    os.mkdir(current_dir)
    print("Selected file: \n",rar_file)
    rar_file = os.path.join(base_path, rar_file)
    extract_nested_rar(rar_file, current_dir)
