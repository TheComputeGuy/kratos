import sys
import time
import os
import copy
import json
import subprocess
import argparse
import magic
from typing import List
from multiprocessing import Pool, cpu_count
from models.base_class import FileMetadata
from models.base_analysis_class import BaseAnalysisClass
from jedi_utils import *
from analysis_rules.analysis_wp_plugin import Analysis_WP_Plugin
from analysis_rules.analysis_mplugin import Analysis_MPlugin
from analysis_rules.analysis_api_abuse import Analysis_API_Abuse
from analysis_rules.analysis_blackhat_seo import Analysis_Blackhat_SEO
from analysis_rules.analysis_downloader import Analysis_Downloader
from analysis_rules.analysis_function_construction import Analysis_Function_Construction
from analysis_rules.analysis_gated_plugin import Analysis_Gated_Plugin
from analysis_rules.analysis_spam import Analysis_Spam

mal_file_analysis_rules: List[BaseAnalysisClass] = [
    Analysis_API_Abuse(),
    Analysis_Blackhat_SEO(),
    Analysis_Downloader(),
    Analysis_Function_Construction(),
    Analysis_Gated_Plugin,
    Analysis_MPlugin(),
    Analysis_Spam(),
]

# Rules that are run only if a file has been flagged as malicious
# Currently only supports reprocessFile method
post_postprocessing_rules: List[BaseAnalysisClass] = [
    # Analysis_Taint_Flow(),          # Analysing malicious data flows within files using taint analysis
]


def do_malicious_file_detection(file_obj: FileMetadata):
    with open(file_obj.filepath, 'r', errors="ignore") as f:
        read_data = f.read()

    try:  # Generate AST for Analysis Passes
        cmd = [
            'php',
            '-f',
            './ast_utils/generateAST.php',
            file_obj.filepath
        ]

        astGenOutput = subprocess.check_output(cmd)

        if astGenOutput:
            file_obj.ast = subprocess.check_output(cmd)
        else:
            file_obj.ast = None

    except Exception as e:
        print("ENCOUNTERED EXCEPTION {} FOR {}".format(e, file_obj.filepath), file=sys.stderr)

    for reanalysis in mal_file_analysis_rules:
        reanalysis.reprocessFile(f_obj = file_obj, r_data = read_data)

    file_obj.clearMemory()

    return file_obj


class Framework:

    def __init__(self, base_path: str) -> None:
        if base_path.endswith("/"):
            pass
        else:
            base_path = base_path + "/"
        
        self.default_name = base_path.strip('/').split('/')[-1]
        self.plugin = get_plugin(base_path)
        self.metadata_analysis: BaseAnalysisClass = Analysis_WP_Plugin()
        self.original_path = base_path

    def get_file_list(self):
        file_list = []
        ma = magic.Magic(mime=True)

        num_files = 0
        # TODO: Check everything under base_path, or just everything?
        for directory_path, subdirectories, filenames in os.walk(self.plugin.plugin_base_path, topdown=True):
            for file in filenames:
                full_file_path = os.path.realpath(os.path.join(directory_path, file))
                if os.path.islink(full_file_path):
                    mime = 'sym_link'
                else:
                    try:
                        mime = ma.from_file(full_file_path.encode("utf-8", 'surrogateescape'))
                    except  Exception as e:
                        print("MIME_ERROR:", e, "Could not encode filename", full_file_path, file=sys.stderr)
                        mime = None
                    file_list.append(FileMetadata(full_file_path, file, mime))
        num_files = len(file_list)

        return file_list, num_files


    def run(self):
        analysis_start = time.time()

        # Create worker pool so the workers are alive always
        worker_pool = Pool(cpu_count())

        files, self.plugin.num_files = copy.deepcopy(self.get_file_list())

        # No point processing anything if the plugin has no files
        if not files:
            exit(204)

        files_to_analyze = []

        for file_obj in files:
            file_obj: FileMetadata = file_obj
            file_obj.extension = get_extension(file_obj.filename)
            if (not is_file_whitelisted(file_obj.filepath) \
                    and ('php' in file_obj.mime_type 
                    or file_obj.filepath == os.path.realpath(os.path.join(self.plugin.plugin_base_path, 'style.css')))):
                files_to_analyze.append(file_obj)

        found_plugin_metadata = False
        for file_obj in files_to_analyze:
            file_obj: FileMetadata = file_obj
            self.plugin, found_plugin_metadata = self.metadata_analysis.processFile(file_obj, self.plugin)
            if found_plugin_metadata:
                # Stop processing if plugin/theme metadata was found
                break

        if not found_plugin_metadata:
            # TODO: What to do if no metadata found? Put some metadata here
            print("NO PLUGIN METADATA FOUND, SKIPPING")
            exit(400)

        mal_detect_output = worker_pool.map(do_malicious_file_detection, files_to_analyze)

        for file_obj in mal_detect_output:
            for analysis in mal_file_analysis_rules:
                analysis.postProcessFile(file_obj)

        # Update the malicious file info
        total_mal_files_count = 0
        mal_files = []
        for file_obj in mal_detect_output:
            if ('php' in file_obj.mime_type):
                if file_obj.suspicious_tags:
                    # If a file is already tagged as malicious, run dataflow to better identify exfil methods
                    for post_analysis in post_postprocessing_rules:
                        post_analysis.post_postProcessFile(file_obj)
                    if file_obj.suspicious_tags:
                        file_obj.is_malicious = True
                        total_mal_files_count += 1
                        mal_files.append(file_obj)
                    else:
                        file_obj.is_malicious = False
                else:
                    file_obj.is_malicious = False

        if total_mal_files_count > 0:
            self.plugin.num_mal_p_files = total_mal_files_count
            for mal_file in mal_files:
                mal_file: FileMetadata = mal_file
                self.plugin.mal_files[mal_file.filepath] = mal_file
            self.plugin.is_mal = True

        if self.plugin.is_mal:
            website_output = process_outputs(self.plugin, analysis_start)

            op_filename = self.plugin.theme_name if self.plugin.is_theme else (self.plugin.plugin_name if self.plugin.plugin_name else self.default_name)
            op_path = "results/" + op_filename + ".json"
            if not os.path.isdir('results'):  # mkdir results if not exists
                os.makedirs('results')

            with open(op_path, 'w') as f:
                f.write(json.dumps(website_output, default=str))

        worker_pool.close()
        worker_pool.join()


if __name__ == "__main__":
    start = time.time()
    
    # TODO: Parsing plugin path when using docker
    parser = argparse.ArgumentParser()
    parser.add_argument("base_path", help="The path of plugin to be analysed")
    args = parser.parse_args()
    base_path = args.base_path

    framework = Framework(base_path=base_path)
    framework.run()

    print("Time taken: ", time.time() - start)
