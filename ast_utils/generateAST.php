<?php
  require_once __DIR__ . '/vendor/autoload.php';

  use PhpParser\ParserFactory;
  use PhpParser\Error;

  $parser = (new ParserFactory)->create(ParserFactory::PREFER_PHP7);
  $filepath = $argv[1];
  $code = file_get_contents($argv[1]);                                    /* Read Code */
  
  $ast = "";
  try                                                             /* Get AST from code */
    { $ast = $parser->parse($code); }
  catch (Error $e) { /* File can't be parsed, invalid PHP? */
    // fwrite(STDERR, "Caught error in parsing file: $filepath" . PHP_EOL);
    // fwrite(STDERR, "$e" . PHP_EOL);
  }
  
  echo json_encode($ast);                                              /* return AST */
?>
