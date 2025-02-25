<?php
// parse CLI options
$args = $argv;
array_shift($args);
$allowedOptions = ["vector", "verbosity", "format", "ignore_warning", "help"];
$options = [];
$path = null;

// parse CLI arguments
while (!empty($args)) {
    $arg = array_shift($args);

    // parse --option=value
    if (strpos($arg, "--") === 0 && strpos($arg, "=") !== false) {
        list($key, $value) = explode("=", substr($arg, 2), 2);
        if (in_array($key, $allowedOptions)) {
            $options[$key] = $value;
        } else {
            die("Error: Unknown option --{$key}\n");
        }
    }
    // parse `--option value`
    elseif (strpos($arg, "--") === 0) {
        $key = substr($arg, 2);
        if (in_array($key, $allowedOptions)) {
            if (!empty($args) && strpos($args[0], "--") !== 0) {
                $options[$key] = array_shift($args);
            } else {
                $options[$key] = true; // default true
            }
        } else {
            die("Error: Unknown option --{$key}\n");
        }
    }
    // parse value of the path
    elseif (!$path) {
        $path = $arg;
    } else {
        die("Error: Unexpected argument '{$arg}'\n");
    }
}

// parse --help
if (isset($options["help"]) || $path == null) {
    echo "Usage: php cli_parser.php /path/to/php/code [--vector=<type>]\n";
    echo "Options:\n";
    echo "  path               (Required) Path to PHP files for analysis.\n";
    echo "  --vector=<type>    (Optional) Attack type filter (xss, sql, exec, include, all). Default: all.\n";
    echo "  --verbosity=<num>  (Optional) (1-5). Default: 1.\n";
    echo "  --format=<type>    (Optional) (readable, json). Default: readable.\n";
    exit(0);
}

// parse `path`
$_POST["loc"] = $path;

// parse `vector`
$_POST["vector"] = $options["vector"] ?? "all";

// parse `verbosity`
$_POST["verbosity"] = $options["verbosity"] ?? 1;

// parse `format`
$output_format = $options["format"] ?? "readable";

// set those options which are prepare for the webUI version
$_POST["subdirs"] = true;
$_POST["ignore_warning"] = true;


###############################  INCLUDES  ################################
include "config/general.php"; // general settings
include "config/sources.php"; // tainted variables and functions
include "config/tokens.php"; // tokens for lexical analysis
include "config/securing.php"; // securing functions
include "config/sinks.php"; // sensitive sinks
include "config/info.php"; // interesting functions

include "lib/constructer.php"; // classes
include "lib/filer.php"; // read files from dirs and subdirs
include "lib/tokenizer.php"; // prepare and fix token list
include "lib/analyzer.php"; // string analyzers
include "lib/scanner.php"; // provides class for scan
include "lib/printer.php"; // output scan result
include "lib/searcher.php"; // search functions

###############################  MAIN  ####################################

$start = microtime(true);

$output = [];
$info = [];
$scanned_files = [];

if (!empty($_POST["loc"])) 
{
    $location = realpath($_POST["loc"]);

    if (is_dir($location)) {
        $scan_subdirs = isset($_POST["subdirs"]) ? $_POST["subdirs"] : false;
        $files = read_recursiv($location, $scan_subdirs);

        if (count($files) > WARNFILES && !isset($_POST["ignore_warning"])) {
            die(
                "warning: the number of files " .
                    count($files) .
                    " over limits. Please use --ignore_warning."
            );
        }
    } 
    elseif (
        is_file($location) &&
        in_array(substr($location, strrpos($location, ".")), $FILETYPES)
    ) 
    {
        $files[0] = $location;
    }
    else {
        $files = [];
    }

    // SCAN
    $user_functions = [];
    $user_functions_offset = [];
    $user_input = [];
    $file_sinks_count = [];
    $count_xss = $count_sqli = $count_fr = $count_fa = $count_fi = $count_exec = $count_code = $count_eval = $count_xpath = $count_ldap = $count_con = $count_other = $count_pop = $count_inc = $count_inc_fail = $count_header = $count_sf = $count_ri = 0;

    $verbosity = isset($_POST["verbosity"]) ? $_POST["verbosity"] : 1;
    $scan_functions = [];
    $info_functions = Info::$F_INTEREST;

    if ($verbosity != 5) {
        switch ($_POST["vector"]) {
            case "xss":
                $scan_functions = $F_XSS;
                break;
            case "httpheader":
                $scan_functions = $F_HTTP_HEADER;
                break;
            case "fixation":
                $scan_functions = $F_SESSION_FIXATION;
                break;
            case "code":
                $scan_functions = $F_CODE;
                break;
            case "ri":
                $scan_functions = $F_REFLECTION;
                break;
            case "file_read":
                $scan_functions = $F_FILE_READ;
                break;
            case "file_affect":
                $scan_functions = $F_FILE_AFFECT;
                break;
            case "file_include":
                $scan_functions = $F_FILE_INCLUDE;
                break;
            case "exec":
                $scan_functions = $F_EXEC;
                break;
            case "database":
                $scan_functions = $F_DATABASE;
                break;
            case "xpath":
                $scan_functions = $F_XPATH;
                break;
            case "ldap":
                $scan_functions = $F_LDAP;
                break;
            case "connect":
                $scan_functions = $F_CONNECT;
                break;
            case "other":
                $scan_functions = $F_OTHER;
                break;
            case "unserialize":
                $scan_functions = $F_POP;
                $info_functions = Info::$F_INTEREST_POP;
                $source_functions = ["unserialize"];
                $verbosity = 2;
                break;
            case "client":
                $scan_functions = array_merge(
                    $F_XSS,
                    $F_HTTP_HEADER,
                    $F_SESSION_FIXATION
                );
                break;
            case "server":
                $scan_functions = array_merge(
                    $F_CODE,
                    $F_REFLECTION,
                    $F_FILE_READ,
                    $F_FILE_AFFECT,
                    $F_FILE_INCLUDE,
                    $F_EXEC,
                    $F_DATABASE,
                    $F_XPATH,
                    $F_LDAP,
                    $F_CONNECT,
                    $F_POP,
                    $F_OTHER
                );
                break;
            case "all":
            default:
                $scan_functions = array_merge(
                    $F_XSS,
                    $F_HTTP_HEADER,
                    $F_SESSION_FIXATION,
                    $F_CODE,
                    $F_REFLECTION,
                    $F_FILE_READ,
                    $F_FILE_AFFECT,
                    $F_FILE_INCLUDE,
                    $F_EXEC,
                    $F_DATABASE,
                    $F_XPATH,
                    $F_LDAP,
                    $F_CONNECT,
                    $F_POP,
                    $F_OTHER
                );
                break;
        }
    }

    if ($_POST["vector"] !== "unserialize") {
        $source_functions = Sources::$F_OTHER_INPUT;
        // add file and database functions as tainting functions
        if ($verbosity > 1 && $verbosity < 5) {
            $source_functions = array_merge(
                Sources::$F_OTHER_INPUT,
                Sources::$F_FILE_INPUT,
                Sources::$F_DATABASE_INPUT
            );
        }
    }

    $overall_time = 0;
    $timeleft = 0;
    $file_amount = count($files);
    for ($fit = 0; $fit < $file_amount; $fit++) {
        // for scanning display
        $thisfile_start = microtime(true);
        $file_scanning = $files[$fit];

        // scan
        $scan = new Scanner(
            $file_scanning,
            $scan_functions,
            $info_functions,
            $source_functions
        );
        $scan->parse();
        $scanned_files[$file_scanning] = $scan->inc_map;

        $overall_time += microtime(true) - $thisfile_start;
        // timeleft = average_time_per_file * file_amount_left
        $timeleft = round(
            ($overall_time / ($fit + 1)) * ($file_amount - $fit + 1),
            2
        );
    }
    #die("done");
    @ob_flush();
    flush();
    echo "STATS_DONE.\n";
}
$elapsed = microtime(true) - $start;

################################  RESULT  #################################
if ($output_format == "readable") 
    printoutput_cli($output, $_POST["treestyle"]);
else if ($output_format == "json") 
    printoutput_json($output, $_POST["treestyle"]);
?>
