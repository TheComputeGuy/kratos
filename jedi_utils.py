from models.base_class import *
import time
import re
import constants.filetypes as filetype_dictionary
from constants.whitelist import whitelisted_files

# Exfil location patterns
emailPattern = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+(?:\.[A-Za-z]{2,4})+")
telegramBotTokenPattern = re.compile(r"\d{8,10}:[\w-]{35}")


def get_extension(file_name):
    is_hidden = False
    if file_name[0] == '.':
        is_hidden = True

    file_types = file_name.split('.')
    possible_filetypes = []
    if len(file_types) > 1 and not is_hidden:
        for filetype in file_types:
            if filetype in filetype_dictionary.readable_to_ext:
                possible_filetypes.append(filetype)
    elif len(file_types) > 2:
        for filetype in file_types:
            if filetype in filetype_dictionary.readable_to_ext:
                possible_filetypes.append(filetype_dictionary.readable_to_ext[filetype])
                possible_filetypes.append(filetype)
    if len(possible_filetypes) > 1:
        for pfg in possible_filetypes:
            if pfg != "svn-base":
                file_extension = pfg
    elif len(possible_filetypes) == 1:
        file_extension = possible_filetypes[0]
        # Re-assigning type for some cases based on extension, only for ease of sorting outputs 
        if file_extension== 'ini':
            file_extension = 'php'
        elif file_extension == 'jsx':
            file_extension = 'js'
        elif (file_extension == 'json') or (file_extension == 'md'):
            file_extension = 'txt'
        elif (file_extension == 'woff') or (file_extension == 'ttf') or (file_extension == 'otf') or (file_extension == 'woff2') or (file_extension == 'eot'):
            file_extension = 'font'
    else:
        file_extension = None
    return file_extension


def process_outputs(plugin: Plugin, analysis_start: float):
    op = {}
    # TODO: Add more context - like download source, etc? Maybe from base path
    # TODO: Add date of upload? If available
    # op["date"] = ??
    op["plugin_name"] = plugin.plugin_name
    op["base_path"] = plugin.plugin_base_path
    op["plugin_version"] = plugin.version
    op["plugin_author"] = plugin.author
    op["plugin_author_uri"] = plugin.author_uri
    op["plugin_plugin_uri"] = plugin.plugin_uri
    op["is_theme"] = plugin.is_theme
    if plugin.is_theme:
        op["theme_name"] = plugin.theme_name
    op["num_files"] = plugin.num_files
    op["tot_mal_files"] = plugin.num_mal_p_files
    op["mal_file_info"] = {}
    if plugin.is_mal:
        for _mal_file in plugin.mal_files:
            mal_file: FileMetadata = plugin.mal_files[_mal_file]
            file_obj = {}
            file_obj["suspicious_tags"] = mal_file.suspicious_tags
            file_obj["extracted_results"] = mal_file.extracted_results
            op["mal_file_info"][mal_file.filepath] = file_obj

    analysis_end = time.time()
    op["time"] = analysis_end - analysis_start

    return op


def is_file_whitelisted(filepath: str) -> bool:
    for filepath_stub in whitelisted_files:
        if filepath_stub in filepath:
            return True
    return False

def get_exfil_locations(read_data: str):
    p0 = re.findall(emailPattern, read_data)
    p1 = re.findall(telegramBotTokenPattern, read_data)

    if not p0:
        p0 = []
    if not p1:
        p1 = []

    return p0, p1


def get_plugin(base_path: str) -> Plugin:
    plugin_base_path = base_path
    for directory_path, subdirectories, filenames in os.walk(base_path, topdown=True):
        for file in filenames:
            if "wpml-config" in file:
                plugin_base_path = os.path.realpath(directory_path)
                break
    
    return Plugin(plugin_path=plugin_base_path)