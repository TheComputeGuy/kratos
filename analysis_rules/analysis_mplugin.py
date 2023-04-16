import re
import json
from sys import argv, path
path.insert(0, '../')
from models.base_analysis_class import BaseAnalysisClass
from models.base_class import FileMetadata

class Analysis_MPlugin(BaseAnalysisClass):
    def __init__(self):
      self.pattern0 = re.compile(r"aerin Singh") # infamous author
      self.pattern1 = re.compile(r"Monetization Code plugin") # infamous plugin name
      self.pattern2 = re.compile(r"register_setting\s*\(\s*\'mplugin-settings\'") # registering "mplugin-settings"
      self.pattern3 = re.compile(r"file_get_contents_mplugin|getVisIpAddr_mplugin|hide_plugin_mplugin") # custom functions
      self.pattern4 = re.compile(r"http://www\.somndo\.\w+") # Suspicious domains

    def reprocessFile(self, file_object, r_data):
      suspicious_file = False
      p0 = re.findall(self.pattern0, r_data)
      p1 = re.findall(self.pattern1, r_data)
      p2 = re.findall(self.pattern2, r_data)
      p3 = re.findall(self.pattern3, r_data)
      p4 = re.findall(self.pattern4, r_data)

      if (p0 and p1):
        suspicious_file = True
        file_object.suspicious_tags.append("MPLUGIN_HEADER")
      if (p2 or p3):
        suspicious_file = True
        file_object.suspicious_tags.append("MPLUGIN_FUNCTIONS")
        file_object.extracted_results["MPLUGIN_FUNCTIONS"] = [p2, p3]
      if (p4):
        suspicious_file = True
        file_object.suspicious_tags.append("MPLUGIN_DOMAINS")
        file_object.extracted_results["MPLUGIN_DOMAINS"] = [p4]
      if(suspicious_file == False):
        if "MPLUGIN_HEADER" in file_object.suspicious_tags:
          file_object.suspicious_tags.remove("MPLUGIN_HEADER")
        if "MPLUGIN_FUNCTIONS" in file_object.suspicious_tags:
          file_object.suspicious_tags.remove("MPLUGIN_FUNCTIONS")
        if "MPLUGIN_DOMAINS" in file_object.suspicious_tags:
          file_object.suspicious_tags.remove("MPLUGIN_DOMAINS")


if __name__=='__main__':  # for debug only
  path.insert(0, '../')
  from models.base_class import FileMetadata
  f_obj = FileMetadata(argv[1], argv[1].split('/')[-1], ['php'])
  with open(f_obj.filepath, 'r', errors="ignore") as f:
    r_data = f.read()

  analysis = Analysis_MPlugin()
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