from varsfile import *
from models.base_analysis_class import BaseAnalysisClass
from models.base_class import Plugin, FileMetadata, PluginFile
import re
import subprocess
import json

class Analysis_WP_Plugin(BaseAnalysisClass):
    def __init__(self):
        self.grouped_plugin = None

    def find_param_str(self, file_read, start_index):
        final_param_str = ""
        open_parentheses = 0
        close_parentheses = 0
        started = False
        while start_index < len(file_read):
            if file_read[start_index] == '(':
                if open_parentheses:
                    final_param_str += file_read[start_index]
                else:
                    started = True
                open_parentheses += 1
            elif file_read[start_index] == ')':
                close_parentheses += 1
                if open_parentheses == close_parentheses:
                    return final_param_str
                else:
                    final_param_str += file_read[start_index]
            elif started:
                final_param_str += file_read[start_index]
            start_index += 1

    def regex_method(self, filepath, file_info, references, score):
        with open(filepath, 'r', errors="ignore") as f:
            file_read = f.read()
        i = 0
        max_score = (2*max(api_score, ref_score, header_score))
        (score, i) = self.find_plugin_header(file_read, file_info, score, i)
        for api in plugin_api:
            rexp = re.compile(func_before_regex + api + func_after_regex)
            iterator = rexp.finditer(file_read)
            for match in iterator:
                score += api_score/(2**i)
                i += 1
                index = match.span()[0]
                if api_keyword not in file_info:
                    file_info[api_keyword] = {}
                if api not in file_info[api_keyword]:
                    file_info[api_keyword][api] = []
                param = self.find_param_str(file_read, index)
                if param:
                    file_info[api_keyword][api].append(param)
        for ref in plugin_ref:
            rexp = re.compile(func_before_regex + ref + func_after_regex)
            iterator = rexp.finditer(file_read)
            for match in iterator:
                score += ref_score/(2**i)
                i += 1
                index = match.span()[0]
                param = self.find_param_str(file_read, index)
                if param:
                    references.append(param)
        formula = ((score*100)/max_score)
        if formula > 0:
            file_info[score_keyword] = str(formula) + "%"

    def find_plugin_header(self, file_read, file_info, score, i):
        #print("FREAD", file_read)
        for ph in plugin_header:
            rexp = re.compile(ph_before_regex + ph + ph_after_regex)
            for match in rexp.finditer(file_read):
                score += header_score/(2**i)
                i += 1
                index = match.span()[0]
                #print("INFO", ph, file_info)
                file_info[ph.rstrip(":")] = file_read[index:].split(':',1)[1].split('\n',1)[0].lstrip()
        return (score, i)

    def ast_method(self, filepath, file_info, refrences, score):
        jstr = subprocess.check_output(
                                        "php -f ast_parser.php \"" + filepath + "\"",
                                        stderr=subprocess.DEVNULL,
                                        shell=True
                                      )
        i = 0
        max_score = (2*max(api_score, ref_score, header_score))
        with open(filepath, 'r', errors="ignore") as f: # GET PLUGIN HEADER INFO
            (score, i) = self.find_plugin_header(f.read(), file_info, score, i)

        jdata = json.loads(jstr.decode('utf-8')) # PUT AST RESULTS INTO JSON
        if len(jdata[api_keyword]) or len(jdata[ref_keyword]):
            file_info[ast_keyword] = jdata
        for api in jdata[api_keyword]:
            score += api_score/(2**i)
            i += 1
        for ref in jdata[ref_keyword]:
            score += ref_score/(2**i)
            i += 1
        formula = ((score*100)/max_score)
        if formula > 0:
            file_info[score_keyword] = str(formula) + "%"

    def processFile(self, file_obj: FileMetadata, plugin_obj: Plugin):
        references = []
        score = 0
        if 'php' in file_obj.mime_type:
            try:
                # Default try AST method
                self.ast_method(file_obj.filepath, file_obj.file_info, references, score)
            except Exception as e:
                # If it fails, switch to RegEx
                self.regex_method(file_obj.filepath, file_obj.file_info, references, score)

            #print("PNAME", f_obj.filepath, f_obj.file_info)
            if plugin_keyword in file_obj.file_info and ("Name of Plugin" not in file_obj.file_info[plugin_keyword]):
                print(file_obj.filepath)
                plugin_name = file_obj.file_info[plugin_keyword]
                file_obj.is_plugin   = True # For all plugins and themes
                file_obj.plugin_name = plugin_name 

                # Assign plugin score
                if score_keyword in file_obj.file_info:
                    plugin_obj.plugin_score = file_obj.file_info[score_keyword] 
                # Assign plugin author
                if wp_author in file_obj.file_info:
                    plugin_obj.author = file_obj.file_info[wp_author]
                # Assign plugin version
                if wp_version in file_obj.file_info:
                    plugin_obj.version= file_obj.file_info[wp_version]
                # Assign plugin author URI
                if wp_author_uri in file_obj.file_info:
                    plugin_obj.author_uri = file_obj.file_info[wp_author_uri]
                # Assign plugin URI
                if wp_plugin_uri in file_obj.file_info:
                    plugin_obj.plugin_uri = file_obj.file_info[wp_plugin_uri]
                # Assign plugin license
                if wp_license in file_obj.file_info:
                    plugin_obj.license = file_obj.file_info[wp_license]
                # Assign plugin description
                if wp_description in file_obj.file_info:
                    plugin_obj.description = file_obj.file_info[wp_description]
                # Save plugin filepath - not used anywhere currently
                # plugin_obj.files[file_obj.filepath] = PluginFile(file_obj.filepath, file_obj.mime_type, plugin_name)
                # It it was a PHP Theme, set theme tag
                if theme_keyword in file_obj.file_info:
                    plugin_obj.is_theme = True
                    print("IS_THEME", file_obj.filepath)
            else:
                file_obj.is_plugin = False
            
            # Free memory holding all of the plugin info in f_obj.file_info
            file_obj.file_info = {}
            return plugin_obj, file_obj.is_plugin
        
        elif "style.css" in file_obj.filename:
            self.populate_other_theme_metadata(file_obj, plugin_obj)
            return plugin_obj, True

    def populate_other_theme_metadata(self, f_obj: FileMetadata, p_obj: Plugin):
        references = []
        score = 0
        self.regex_method(f_obj.filepath, f_obj.file_info, references, score)
        # Assign plugin score
        if score_keyword in f_obj.file_info:
            p_obj.plugin_score = f_obj.file_info[score_keyword] 
        # Assign plugin author
        if wp_author in f_obj.file_info:
            p_obj.author = f_obj.file_info[wp_author]
        # Assign plugin version
        if wp_version in f_obj.file_info:
            p_obj.version= f_obj.file_info[wp_version]
        # Assign plugin author URI
        if wp_author_uri in f_obj.file_info:
            p_obj.author_uri = f_obj.file_info[wp_author_uri]
        # Assign plugin URI
        if wp_theme_uri in f_obj.file_info:
            p_obj.plugin_uri = f_obj.file_info[wp_theme_uri]
        # Assign plugin license
        if wp_license in f_obj.file_info:
            p_obj.license = f_obj.file_info[wp_license]
        # Assign plugin description
        if wp_description in f_obj.file_info:
            p_obj.description = f_obj.file_info[wp_description]
        # Assign theme name 
        if theme_keyword in f_obj.file_info:
            p_obj.theme_name = f_obj.file_info[theme_keyword]

