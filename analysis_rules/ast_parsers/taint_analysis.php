<?php

define('__VENDOR_DIR__', dirname(dirname(__DIR__)) . '/ast_utils/vendor');

require_once __VENDOR_DIR__ . '/autoload.php';

$filepath = fgets(STDIN);                   /* Read filepath from python STDIN pipe */

/********** ProgPilot **********/
$context = new \progpilot\Context;                            /* progpilot context */
$analyzer = new \progpilot\Analyzer;                        /* taint analysis pass */

$context->inputs->setFile($filepath);                        /* configure analysis */
$context->setConfiguration(__DIR__ . "/progpilot_config/config.yml");
$context->inputs->setSources(__DIR__ . "/progpilot_config/sources.json");
$context->inputs->setSinks(__DIR__ . "/progpilot_config/sinks.json");
$context->inputs->setCustomRules(__DIR__ . "/progpilot_config/rules.json");
$context->inputs->setSanitizers(__DIR__ . "/progpilot_config/sanitizers.json");
$context->inputs->setValidators(__DIR__ . "/progpilot_config/validators.json");

$analyzer->run($context);                                    /* run taint analysis */

/********** Results **********/
$results = $context->outputs->getResults();

if (sizeof($results) != 0) {
    echo json_encode(
        array(
            "progpilot" => $results
        )
    );
}

?>