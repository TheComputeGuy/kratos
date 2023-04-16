import os
from sys import argv, path
path.insert(0, '../')
from models.base_analysis_class import BaseAnalysisClass
import json, subprocess

class Analysis_Spam(BaseAnalysisClass):
  def __init__(self):
    dir_path = os.path.dirname(os.path.realpath(__file__))
    parser_path = dir_path + '/ast_parsers/spam_parser.php'
    self.parser_cmd = [
                        'php', '-f',
                        parser_path
                    ]

  def reprocessFile(self, file_object, r_data=None):
    if 'php' not in file_object.mime_type:                               # only process if PHP
      return

    elif file_object.ast is None:                               # can't process without an AST
      return

    else:                                                         # Detect Spam Injection
      try:                                                                   # Run Parser
        spam_parser = subprocess.Popen(
                                        self.parser_cmd, 
                                        stdout = subprocess.PIPE, 
                                        stdin  = subprocess.PIPE,
                                        stderr = subprocess.PIPE
                                      )

        spam_out, spam_err = spam_parser.communicate(file_object.ast)    # send AST over stdin

      except subprocess.CalledProcessError:                        # Something went wrong
        pass

      if spam_err:
        #print()
        #print(spam_err.decode())
        #print()
        return
      elif spam_out:
        spam_out = json.loads(spam_out.decode('utf-8'))              # Decode JSON result
      else:
        return

      # print()
      # print(json.dumps(spam_out, indent=2))
      # print()
      
      if len(spam_out) > 0:                                      # Did we find any links?
        if 'SPAM_INJECTION' not in file_object.suspicious_tags:
          file_object.suspicious_tags.append('SPAM_INJECTION')
        file_object.extracted_results.update({'SPAM_INJECTION':spam_out})
      else:
        if 'SPAM_INJECTION' in file_object.suspicious_tags:
          file_object.suspicious_tags.remove('SPAM_INJECTION')
      
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

  SI = Analysis_Spam()
  SI.reprocessFile(f_obj)

  print('Plugin File Object:')
  print('------------------------------------------')
  print('Plugin Name: {}'.format(f_obj.plugin_name))
  print('Mime Type:   {}'.format(f_obj.mime_type))
  print('Tags:        {}'.format(f_obj.suspicious_tags))
  print('Malicious:   {}'.format(f_obj.is_malicious))
  print('Results:\n{}'.format(json.dumps(f_obj.extracted_results, indent=2)))
  print()