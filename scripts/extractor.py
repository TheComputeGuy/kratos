import zipfile, re, os, argparse

def extract_nested_zip(zippedFile, toFolder):
    """ Extract a zip file including nested zip files
        Delete the zip file(s) after extraction
    """
    with zipfile.ZipFile(zippedFile, 'r') as zfile:
        zfile.extractall(path=toFolder)
    os.remove(zippedFile)
    for root, dirs, files in os.walk(toFolder):
        for filename in files:
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

# filter for only the zip files
zip_files = [f for f in files_in_dir if f.endswith('.zip')]

# extract all the nested zip files
for zip_file in zip_files:
    current_dir = base_path
    zip_dir_name = zip_file.replace(".zip", "")
    current_dir=current_dir+"/"+zip_dir_name
    current_dir = current_dir.strip()
    os.mkdir(current_dir)
    print("Selected file: \n",zip_file)
    zip_file = os.path.join(base_path, zip_file)
    try:
        extract_nested_zip(zip_file, current_dir)
    except Exception:
        continue

