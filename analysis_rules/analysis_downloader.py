import os
from sys import argv, path
path.insert(0, '../')
from models.base_analysis_class import BaseAnalysisClass
import json, subprocess
from vt import *
from urllib.parse import urlparse
from constants.malicious_urls import *
from constants.clean_urls import *

class Analysis_Downloader(BaseAnalysisClass):
  def __init__(self):
    dir_path = os.path.dirname(os.path.realpath(__file__))
    parser_path = dir_path + '/ast_parsers/downloader_parser.php'
    self.parser_cmd = [
                        'php', '-f',
                        parser_path
                    ]

  def reprocessFile(self, file_object, r_data=None):
    str_lst = ["$basicAuth", "https://%s", "https://$domain", "http://localhost", "this->", "str_replace", "'", '"', "$"]
    red_flags = ["REMOTE_ADDR", "HTTP_HOST", "HTTP_USER_AGENT"]
    if 'php' not in file_object.mime_type:                               # only process if PHP
      return
    
    elif file_object.ast is None:                               # can't process without an AST
      return

    else:                                                  # Detect Function Construction
      try:                                                                   # Run Parser
        dl_parser = subprocess.Popen(
                                      self.parser_cmd, 
                                      stdout = subprocess.PIPE, 
                                      stdin  = subprocess.PIPE,
                                      stderr = subprocess.PIPE,
                                    )
                                    
        dl_out, dl_err = dl_parser.communicate(file_object.ast)     # send AST over stdin pipe

      except subprocess.CalledProcessError:                        # Something went wrong
        #print("Exception")
        return

      if dl_err:
        #print("DL_ERR")
        #print(dl_err.decode())
        #print()
        return
      elif dl_out:
        dl_out = json.loads(dl_out.decode('utf-8'))
        #print("DL_OUT", dl_out)
      else:
        return

      # print()
      # print(json.dumps(dl_out, indent=2)) # debug
      # print()

      dl = False
      dl1 = False
      dl2 = False
      res = []

      # process DL_Parser Output
      if len(dl_out['downloaders_1']) > 0:
        dl = True
        dl1 = True
      if len(dl_out['downloaders_2']) > 0:
        dl = True
        dl2 = True


      # For downloader that downloads from a URL, pass it through VT and check if the domain is malicious
      for d in dl_out:
        for l in dl_out[d]:
          valid_url = False
          url = l["URL"]
          url = url.strip('"')
          url = url.strip("'")
          https = ['https://', 'http://', 'hxxp://', 'httx://']
          for htt in https:
            if htt in url: 
                #print("HTT", htt, url)
                #print()
                if url.startswith(htt):
                    valid_url = True
                    break
                else:
                    url = htt + url.split(htt,1)[1]
                    #print("URL", url)
                valid_url = True

          if valid_url:
            #print("VALID", url)
            p = urlparse(url)
            if not p[0] or not p[1]:
                s = url.split("/")
                domain = s[0] + "/" + s[1] + "/" + s[2] +"/"
            elif (not p[0]) and (not p[1]):
                dl = False
            else:
                domain = p[0] + "://" + p[1]

            #print("DOMAIN", domain)
            if any(stng in domain for stng in str_lst):
                dl = False

            if dl and "LogglyHandler.php" not in file_object.filepath :
                for c_url in c_urls:
                    if c_url in domain:
                        dl = False
                for m_url in m_urls:
                    if m_url in domain:
                        res = "Known Malicious"
                        break
                if res:
                    if "VT" not in l:
                        l["VT"] = {}
                    l["VT"][url] = res
                if not res:
                    if any(fl in url for fl in red_flags):
                        res = "Content Injection"
                        if "VT" not in l:
                            l["VT"] = {}
                        l["VT"][url] = res
                    elif str(domain) not in self.analyzed_links:
                        #print("DOMAIN", str(domain))
                        res = run_VT_scan(str(domain))
                        self.analyzed_links[str(domain)] = res
                        if not res:
                            dl = False
                        else:
                            if "VT" not in l:
                                l["VT"] = {}
                            l["VT"][url] = res
                    else:
                        if self.analyzed_links[domain] in ["GET_REPORT_FAIL", "SCAN_FAIL"]:
                            res = run_VT_scan(str(domain))
                            self.analyzed_links[str(domain)] = res
                            if not res:
                                dl = False
                            else:
                                if "VT" not in l:
                                    l["VT"] = {}
                                l["VT"][url] = res
                        if self.analyzed_links[str(domain)]:
                            if "VT" not in l:
                                l["VT"] = {}
                            l["VT"][url] = self.analyzed_links[str(domain)]
                        else:
                            dl = False
            #print("RES", res)

      # If VT scan fails
      categorize_later= False
      for d in dl_out:
          if dl_out[d]:
              for e in dl_out[d]:
                  if "VT" in e:
                      for url in e["VT"]:
                          if any(fl in url for fl in red_flags):
                              categorize_later= False
                              break
                          if "results" in e["VT"][url]:
                              categorize_later = True


      if dl and not categorize_later: 
        if (dl2 and valid_url) or dl1:
            if 'DOWNLOADER' not in file_object.suspicious_tags:
                file_object.suspicious_tags.append('DOWNLOADER')
                file_object.extracted_results.update({'DOWNLOADER':dl_out})
      elif dl and categorize_later:
        if 'MAYBE_DOWNLOADER' not in file_object.suspicious_tags:
          file_object.suspicious_tags.append('MAYBE_DOWNLOADER')
        file_object.extracted_results.update({'MAYBE_DOWNLOADER':dl_out})
      else:
        if 'DOWNLOADER' in file_object.suspicious_tags:
          file_object.suspicious_tags.remove('DOWNLOADER')
        if 'MAYBE_DOWNLOADER' in file_object.suspicious_tags:
          file_object.suspicious_tags.remove('MAYBE_DOWNLOADER')
      
if __name__=='__main__':  # for debug only
  path.insert(0, '../')
  from models.base_class import FileMetadata
  f_obj = FileMetadata(argv[1], argv[1].split('/')[-1], ['php'])

  try:    # Generate AST for Analysis Pass
    parent_dir_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    parser_path = parent_dir_path + '/ast_utils/generateAST.php'
    get_ast = ['php', '-f', parser_path, f_obj.filepath]
    f_obj.ast = subprocess.check_output(get_ast)
    
  except Exception as e:
    pass

  SI = Analysis_Downloader()
  SI.reprocessFile(f_obj)

  print('Plugin File Object:')
  print('------------------------------------------')
  print('Plugin Name: {}'.format(f_obj.plugin_name))
  print('Mime Type:   {}'.format(f_obj.mime_type))
  print('Tags:        {}'.format(f_obj.suspicious_tags))
  print('Malicious:   {}'.format(f_obj.is_malicious))
  print('Results:\n{}'.format(json.dumps(f_obj.extracted_results, indent=2)))
  print()