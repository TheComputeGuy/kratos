import os
from sys import argv, path
path.insert(0, '../')
from models.base_analysis_class import BaseAnalysisClass
import json, subprocess

class Analysis_API_Abuse(BaseAnalysisClass):
  def __init__(self):
    dir_path = os.path.dirname(os.path.realpath(__file__))
    parser_path = dir_path + '/ast_parsers/api_abuse_parser.php'
    self.parser_cmd = [
                        'php', '-f',
                        parser_path
                    ]

  def reprocessFile(self, file_object, r_data=None):

    if 'php' not in file_object.mime_type:                               # only process if PHP
      return
    
    elif file_object.ast is None:                               # can't process without an AST
      return

    else:                                                              # Detect API Abuse
      try:                                                                   # Run Parser
        api_parser = subprocess.Popen(
                                      self.parser_cmd, 
                                      stdout = subprocess.PIPE, 
                                      stdin  = subprocess.PIPE,
                                      stderr = subprocess.PIPE,
                                    )
                                    
        api_out, api_err = api_parser.communicate(file_object.ast)  # send AST over stdin pipe

      except subprocess.CalledProcessError:                        # Something went wrong
        return

      if api_err:
        # print("ERR")
        # print(api_err.decode())
        # print()
        return
      elif api_out:
        api_out = json.loads(api_out.decode('utf-8'))
      else:
        return

      # print("API OUT")
      # print()
      # print(json.dumps(api_out, indent=2)) # debug
      # print()
    
      # Process API_Parser Output:
      if len(api_out['disable_plugins']):                                # Disabling Plugins
        if 'DISABLE_ALL_PLUGINS' not in file_object.suspicious_tags:
          file_object.suspicious_tags.append('DISABLE_ALL_PLUGINS')
        file_object.extracted_results.update({'DISABLE_ALL_PLUGINS':api_out['disable_plugins']})
      else:
        if 'DISABLE_ALL_PLUGINS' in file_object.suspicious_tags:
          file_object.suspicious_tags.remove('DISABLE_ALL_PLUGINS')

      if len(api_out['user_enum']):                            # User (Admin) Enumeration
        if 'USER_ENUM' not in file_object.suspicious_tags:
          file_object.suspicious_tags.append('USER_ENUM')
        file_object.extracted_results.update({'USER_ENUM':api_out['user_enum']})
      else:
        if 'USER_ENUM' in file_object.suspicious_tags:
          file_object.suspicious_tags.remove('USER_ENUM')

      if len(api_out['post_insert']) >= 6:                            # Malicious Post Insert
        funcs = set()
        for l_item in api_out['post_insert']:
          funcs.add(l_item.split(":")[1])
        if len(funcs) >= 6:  
          if 'POST_INSERT' not in file_object.suspicious_tags:
            file_object.suspicious_tags.append('POST_INSERT')
            file_object.extracted_results.update({'POST_INSERT':api_out['post_insert']})
        else:
          if 'POST_INSERT' in file_object.suspicious_tags:
            file_object.suspicious_tags.remove('POST_INSERT')
      else:
        if 'POST_INSERT' in file_object.suspicious_tags:
          file_object.suspicious_tags.remove('POST_INSERT')

      if len(api_out['spam_down']) >= 11:                            # Spam + downloader
        funcs = set()
        for l_item in api_out['spam_down']:
          funcs.add(l_item.split(":")[1])
        if len(funcs) >= 11:  
          if 'SPAM_DOWN' not in file_object.suspicious_tags:
            file_object.suspicious_tags.append('SPAM_DOWN')
            file_object.extracted_results.update({'SPAM_DOWN':api_out['spam_down']})
        else:
          if 'SPAM_DOWN' in file_object.suspicious_tags:
            file_object.suspicious_tags.remove('SPAM_DOWN')
      else:
        if 'SPAM_DOWN' in file_object.suspicious_tags:
          file_object.suspicious_tags.remove('SPAM_DOWN')

      if len(api_out['user_insert']):                             # User (Admin) Creation
        if 'USER_INSERT' not in file_object.suspicious_tags:
          #print("PNAME", pf_obj.plugin_name)
          if file_object.plugin_name not in ['Elegant Themes Support', 'InsideOut Solutions Hosting Extras', 'stability', 'Superadmin', 'Pirate Parrot']:
            file_object.suspicious_tags.append('USER_INSERT')
            file_object.extracted_results.update({'USER_INSERT':api_out['user_insert']})
      else:
        if 'USER_INSERT' in file_object.suspicious_tags:
            file_object.suspicious_tags.remove('USER_INSERT')

      if len(api_out['check4get']):                              # Check for GET function
        if 'CHECK_FOR_GET' not in file_object.suspicious_tags:
          file_object.suspicious_tags.append('CHECK_FOR_GET')
        file_object.extracted_results.update({'CHECK_FOR_GET':api_out['check4get']})
      else:
        if 'CHECK_FOR_GET' in file_object.suspicious_tags:
          file_object.suspicious_tags.remove('CHECK_FOR_GET')

      if len(api_out['fake_plugin']) >= 2:                        # Fake Plugin Functions
        if 'FAKE_FUNCTIONS' not in file_object.suspicious_tags:
          file_object.suspicious_tags.append('FAKE_FUNCTIONS')
        file_object.extracted_results.update({'FAKE_FUNCTIONS':api_out['fake_plugin']})
      else:
        if 'FAKE_FUNCTIONS' in file_object.suspicious_tags:
          file_object.suspicious_tags.remove('FAKE_FUNCTIONS')
    
      if len(api_out['user_backdoor']) >= 6:         # User Info Based Backdoor Functions
        funcs = set()
        for l_item in api_out['user_backdoor']:
          funcs.add(l_item.split(":")[1])
        if len(funcs) >= 6:  
          if 'USER_INFO_BASED_BACKDOOR' not in file_object.suspicious_tags:
            file_object.suspicious_tags.append('USER_INFO_BASED_BACKDOOR')
          file_object.extracted_results.update({'USER_INFO_BASED_BACKDOOR':api_out['user_backdoor']})
        else:
          if 'USER_INFO_BASED_BACKDOOR' in file_object.suspicious_tags:
            file_object.suspicious_tags.remove('USER_INFO_BASED_BACKDOOR')
      else:
        if 'USER_INFO_BASED_BACKDOOR' in file_object.suspicious_tags:
          file_object.suspicious_tags.remove('USER_INFO_BASED_BACKDOOR')
      
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

  SI = Analysis_API_Abuse()
  SI.reprocessFile(f_obj)

  print('Plugin File Object:')
  print('------------------------------------------')
  print('Plugin Name: {}'.format(f_obj.plugin_name))
  print('Mime Type:   {}'.format(f_obj.mime_type))
  print('Tags:        {}'.format(f_obj.suspicious_tags))
  print('Malicious:   {}'.format(f_obj.is_malicious))
  print('Results:\n{}'.format(json.dumps(f_obj.extracted_results, indent=2)))
  print()