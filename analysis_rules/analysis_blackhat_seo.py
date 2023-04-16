import os
from sys import argv, path
path.insert(0, '../')
from models.base_analysis_class import BaseAnalysisClass
import json, subprocess
from vt import *
from urllib.parse import urlparse
from constants.malicious_urls import *
from constants.clean_urls import *

class Analysis_Blackhat_SEO(BaseAnalysisClass):
  def __init__(self):
    dir_path = os.path.dirname(os.path.realpath(__file__))
    parser_path = dir_path + '/ast_parsers/blackhat_seo_parser.php'
    self.parser_cmd = [
                        'php', '-f',
                        parser_path
                    ]

  def reprocessFile(self, file_object, r_data=None):
    if 'php' not in file_object.mime_type:                               # only process if PHP
      return
    else:                                                           # Detect Blackhat SEO
      try:                                                                   # Run Parser
        bs_parser = subprocess.Popen(
                                      self.parser_cmd, 
                                      stdout=subprocess.PIPE, 
                                      stdin=subprocess.PIPE
                                    )
        bs_out, bs_err = bs_parser.communicate(file_object.ast)

      except subprocess.CalledProcessError as e:                   # Something went wrong
        print("ERROR:", e, "while parsing file", file_object.filepath)

      if bs_err:
        return
      elif bs_out:
        bs_out = bs_out.decode('utf-8')
      else:
        return

      detected_links = None
      if len(bs_out):
        bs_out = json.loads(bs_out)     
        if bs_out['detected'] == "True":
          detected_links = bs_out['detected_links']
      
      if detected_links is not None:
        vt_results = {}
        for link in detected_links:
            valid_url = False
            #print("LINK", link)
            url_link  = link['URL']
            #print("LINK", url_link)

            url_link = url_link.strip('"')
            url_link = url_link.strip("'")
            https = ['https://', 'http://', 'hxxp://', 'httx://']
            for htt in https:
                if htt in url_link: 
                    if url_link.startswith(htt):
                        valid_url = True
                        break 
                    else:
                        url_link = htt + url.split(htt,1)[1]
                    valid_url = True

            if valid_url:
                #print("VALID", url_link)
                p = urlparse(url_link)
                if not p[0] or not p[1]:
                    s = url_link.split("/")
                    domain = s[0] + "/" + s[1] + "/" + s[2] +"/"
                elif (not p[0]) and (not p[1]):
                    domain = ""
                else:
                    domain = p[0] + "://" + p[1]
                
                #if str(domain) not in self.analyzed_links:
                    #print("DOMAIN", str(domain))

                # Analyze only the Domain on VT
                if domain:
                    #print("IFDOMAIN", str(domain))
                    # If URL is clean, don't run VT scan
                    for c_url in c_urls:
                        #print("C_URL", c_url, domain)
                        if c_url in domain:
                            domain = "" 
                            break

                    if domain:
                        # Else run VT Scan        
                        if str(domain) in m_urls:
                            vt_results[str(url_link)] = "Known Malicious"
                        elif str(domain) not in self.analyzed_links:
                            res = run_VT_scan(str(domain))
                            self.analyzed_links[str(domain)] = res
                            #print("VT RES", res)
                            if res:
                                vt_results[str(url_link)] = res
                        else:
                            if self.analyzed_links[domain] in ["GET_REPORT_FAIL", "SCAN_FAIL"]:
                                res = run_VT_scan(str(domain))
                                self.analyzed_links[str(domain)] = res
                                if res:
                                    vt_results[str(url_link)] = res

                            if self.analyzed_links[str(domain)]:
                                vt_results[str(url_link)] = self.analyzed_links[str(domain)]

        if  vt_results:
            del_links = [] 
            for link in vt_results:
                # Invalid URL cases remove
                if 'results' in vt_results[link]:
                    if "Invalid" in vt_results[link]['results']['verbose_msg']:
                        del_links.append(link)
                        continue
            for link in del_links:
                del vt_results[link]
        if vt_results:
            categorize_later = False
            for url in vt_results:
                if "results" in vt_results[url]:
                    categorize_later = True

            if 'SEO' not in file_object.suspicious_tags and not categorize_later:
                file_object.suspicious_tags.append('SEO')
                file_object.extracted_results.update({'SEO': vt_results})
            elif  categorize_later:
                if 'MAYBE_SEO' not in file_object.suspicious_tags:
                    file_object.suspicious_tags.append('MAYBE_SEO')
                    file_object.extracted_results.update({'MAYBE_SEO':vt_results})
        else:
          if 'SEO' in file_object.suspicious_tags:
            file_object.suspicious_tags.remove('SEO')
          if 'MAYBE_SEO' in file_object.suspicious_tags:
            file_object.suspicious_tags.remove('MAYBE_SEO')
      
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

  SI = Analysis_Blackhat_SEO()
  SI.reprocessFile(f_obj)

  print('Plugin File Object:')
  print('------------------------------------------')
  print('Plugin Name: {}'.format(f_obj.plugin_name))
  print('Mime Type:   {}'.format(f_obj.mime_type))
  print('Tags:        {}'.format(f_obj.suspicious_tags))
  print('Malicious:   {}'.format(f_obj.is_malicious))
  print('Results:\n{}'.format(json.dumps(f_obj.extracted_results, indent=2)))
  print()