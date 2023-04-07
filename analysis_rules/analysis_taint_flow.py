import subprocess
from collections import defaultdict
import json
from sys import argv, path
path.insert(0, '../')
from models.base_analysis_class import BaseAnalysisClass
from models.base_class import FileMetadata
import os

def getZero():
    return 0

class Analysis_Taint_Flow(BaseAnalysisClass):
    def __init__(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        parser_path = dir_path + '/ast_parsers/taint_analysis.php'
        self.parser_cmd = [
                        'php', '-f',
                        parser_path
                    ]

    def post_postProcessFile(self, f_obj: FileMetadata, r_data = None):
        if 'php' not in f_obj.mime_type:
            return
        else:
            try:                                                                    # Run Parser
                parser = subprocess.Popen(
                                                self.parser_cmd,
                                                stdout = subprocess.PIPE,
                                                stdin  = subprocess.PIPE,
                                                stderr = subprocess.PIPE,
                                            )
                p_out, p_err = parser.communicate(input = f_obj.filepath.encode('utf-8'), timeout=100)          # send filepath over stdin
            except subprocess.TimeoutExpired:
                print("Taint analysis timed out for file:", f_obj.filepath)
                parser.kill()
                return
            except subprocess.CalledProcessError:                                   # Something went wrong
                pass

            if p_err:
                # print("File: ", f_obj.filepath)
                # print("Got error when processing taint analysis: ", p_err.decode('utf-8'))
                print("Got error when processing taint analysis for file:", f_obj.filepath)
                parser.kill()
                return
            elif p_out:
                try:
                    p_out = json.loads(p_out.decode('utf-8'))
                except Exception as e:
                    print("File: ", f_obj.filepath)
                    print("Got erroneous output:", p_out.decode('utf-8'))
                    return
            else:
                return

            if len(p_out) > 0:
                progpilot_hits = list(dict(p_out)['progpilot'])
                results = defaultdict(getZero)
                for hit in progpilot_hits:
                    hit = dict(hit)
                    vuln_name: str = hit['vuln_name']
                    results[vuln_name] += 1

                if 'TAINTED_DATA_FLOW' not in f_obj.suspicious_tags:
                    f_obj.suspicious_tags.append('TAINTED_DATA_FLOW')
                    f_obj.extracted_results.update({'TAINTED_DATA_FLOW':results})
            else:
                if 'TAINTED_DATA_FLOW' in f_obj.suspicious_tags:
                    f_obj.suspicious_tags.remove('TAINTED_DATA_FLOW')
                    f_obj.extracted_results.pop('TAINTED_DATA_FLOW', '')
            return

if __name__=='__main__':  # for debug only
    path.insert(0, '../')
    from models.base_class import FileMetadata
    f_obj = FileMetadata(argv[1], argv[1].split('/')[-1], ['php'])
    with open(f_obj.filepath, 'r', errors="ignore") as f:
        r_data = f.read()

    analysis = Analysis_Taint_Flow()
    analysis.reprocessFile(f_obj, r_data)

    if len(f_obj.suspicious_tags):
        f_obj.is_malicious = True
    else:
        f_obj.is_malicious = False

    print('File Object:')
    print('------------------------------------------')
    print('Mime Type:   {}'.format(f_obj.mime_type))
    print('Tags:        {}'.format(f_obj.suspicious_tags))
    print('Malicious:   {}'.format(f_obj.is_malicious))
    print('Extracted Results: ')
    print(json.dumps(f_obj.extracted_results, indent=2))
    print()