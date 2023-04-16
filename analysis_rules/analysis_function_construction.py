import os
from sys import argv, path
path.insert(0, '../')
from models.base_analysis_class import BaseAnalysisClass
import json, subprocess

class Analysis_Function_Construction(BaseAnalysisClass):
  def __init__(self):
    dir_path = os.path.dirname(os.path.realpath(__file__))
    parser_path = dir_path + '/ast_parsers/fc_parser.php'
    self.parser_cmd = [
                        'php', '-f',
                        parser_path
                    ]

    self.skip_files = [
                        '/date/date_api/date_api.module'
                        '/phpseclib/Net/SSH2.php'
                      ]

    self.whitelist = [
                        "radium-importer.php",
                        "yellow-pencil.php",
                        "ot-functions-admin.php",
                        "option_table_export.php",
                        "option-tree",
                        "dental-care",
                        "nanosoft"
                      ]

    self.whitelist_funcs = [
                            "ot_decode", 
                            "optiontree_decode", 
                            "alchem_decode", 
                            "yp_decode"
                          ]

  def reprocessFile(self, file_object, r_data):
    if any(string in file_object.filepath for string in self.whitelist):
      return

    if any(string in r_data for string in self.whitelist_funcs):
      return

    if 'php' not in file_object.mime_type:                               # only process if PHP
      return
    
    elif file_object.ast is None:                               # can't process without an AST
      return

    else:                                                  # Detect Function Construction
      
      for skip in self.skip_files:                         # but first check if skip_file
        if skip in file_object.filepath:
          return


      try:                                                                   # Run Parser
        fc_parser = subprocess.Popen(
                                      self.parser_cmd,
                                      stdout = subprocess.PIPE,
                                      stdin  = subprocess.PIPE,
                                      stderr = subprocess.PIPE,
                                    )
                                    
        fc_out, fc_err = fc_parser.communicate(                # send AST over stdin pipe
                                                input=file_object.ast,
                                                timeout=5*60              # 5 min timeout
                                              )

      except subprocess.CalledProcessError:                        # Something went wrong
        return
      except subprocess.TimeoutExpired:
        fc_parser.terminate()
        return

      if fc_err:
        return
      elif fc_out:
        fc_out = json.loads(fc_out.decode('utf-8'))
      else:
        return

      # print()
      # print(json.dumps(fc_out, indent=2)) # debug
      # print()
      
      fc = False

      # process FC_Parser Output
      if (len(fc_out['constructed']) > 0) and fc_out['progpilot']:
        for result in fc_out['progpilot']:
          for func in fc_out['constructed']:
            if 'source_name' in result:
              if func in result['source_name']:
                fc = True
            if 'sink_name' in result:
              if func in result['sink_name']:
                fc = True
            if 'tainted_flow' in result:
              for taint in result['tainted_flow']:
                for t in taint:
                  if (func+'_return') in t['flow_name']:
                    fc = True

        if fc:                   # functions were constructed and progpilot found a taint
          if 'FUNCTION_CONSTRUCTION' not in file_object.suspicious_tags:
            file_object.suspicious_tags.append('FUNCTION_CONSTRUCTION')
          file_object.extracted_results.update({'FUNCTION_CONSTRUCTION':fc_out['constructed']})
        else:
          if 'FUNCTION_CONSTRUCTION' in file_object.suspicious_tags:
            file_object.suspicious_tags.remove('FUNCTION_CONSTRUCTION')
  
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

  SI = Analysis_Function_Construction()
  SI.reprocessFile(f_obj)

  print('Plugin File Object:')
  print('------------------------------------------')
  print('Plugin Name: {}'.format(f_obj.plugin_name))
  print('Mime Type:   {}'.format(f_obj.mime_type))
  print('Tags:        {}'.format(f_obj.suspicious_tags))
  print('Malicious:   {}'.format(f_obj.is_malicious))
  print('Results:\n{}'.format(json.dumps(f_obj.extracted_results, indent=2)))
  print()