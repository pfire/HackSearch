<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */
/**
 * PHP HackSearch CLI Version
 * Scan the current directory and all its subfolders for malicious code.
 * PHP version 5.3.10+ required!
 *
 * @category   HackSearch
 * @package    HackSearch CLI
 * @author     Valeri Markov <val@phpfire.net>
 * @copyright  2012-2017 Valeri Markov
 * @license    MIT
 * @version    2.3.0
 * @link       http://www.phpfire.net/hacksearch.phar
 * @since      File available since Release 2.0.0
 */
 
define("HS_VERSION","2.3.0");

/* Setup some php variables */
set_time_limit(0);
ini_set('memory_limit','512M');
date_default_timezone_set('Europe/Sofia');

/* Parse the command line args*/
$shortopts  = "";
$shortopts .= "o:";// Writes output to file. Turns on quiet mode as well.
$shortopts .= "s";// Short mode. Do not print why the file has been detected as malicious.
$shortopts .= "f:";// If -o is present, determines the format the file will have. Available values are: txt, xml, json
$shortopts .= "q";// Quiet mode. Supress all output until the end of the script, when the final result is presented.

$longopts  = array(
    "target:",   // Change the directory to be scanned to "target"
    "appfocus:", // Add an application focus. Available options are Joomla and WordPress
    "no-malware-scan", // Disable the malware scan feature
    "help",     // Show the help screen and exit.
    "version",  // Show the version number and exit.
    "license"   // Show the license screen and exit.
);
$options = getopt($shortopts, $longopts);

//Clean the above mess.
unset($shortopts, $longopts);

/* Scanner Class */
class FileScanner {

   private $total_rules = 7;
   private $total_global_rules = 6;
   private $contents = "";
   private $reg = array();
   public $score = 0;
   private $f;

   public $explain = array(); 

   public function scan($f)
   {
      /* We do not really want to scan all type of files. The following are excluded:
       * PDF Files
       * Doc, Docx Files
       * Avi, MDF, MOV, MPG and MPEG movie type of files
       * PSD Photoshop files
       * Zip, Tar, gz, 7zip, Rar archive files
       * Mo language files
       */
      $excludes = array('pdf','doc','docx','avi','mdf','mov','mpg','mpeg','psd','zip','tar','gz','7zip','rar','mo');
      if(in_array($f->getExtension(),$excludes))
      {
      	return false;
      }
      
      $this->f = $f;
      $contents = file($f->getRealPath(), FILE_IGNORE_NEW_LINES  |FILE_SKIP_EMPTY_LINES);
      foreach($contents as $line){
         for($i=1;$i <= $this->total_rules; $i++){
         	if($this->score > 99){
             	return true;
        	}
            $rule_name = "rule_".$i;
            $this->$rule_name($line);
            $this->contents .= $line;
         }
      }
        
        //Return at this point if line based checks found too suspicious code
        if($this->score > 99){
             return true;
        } 

      //Run global function scans
      for($i=1;$i <= $this->total_global_rules;$i++){
         $global_rule_name = "global_rule_".$i;
         $this->$global_rule_name();
         if($this->score > 99){
             	return true;
        }
      }

      if($this->score > 99){
         return true;
      }
      //.htaccess thing
      $this->check_htaccess();

   }

    private function check_htaccess()
    {
    	if($this->f->getFilename() == ".htaccess"){
    	    if(stripos($this->contents,'google') !== FALSE AND stripos($this->contents,'HTTP_REFERER') !== FALSE){
        		$this->score += 100;
        		$this->explain[] = "[htaccess_referer]";
    	    }
    	}
    }

   private function global_rule_1()
   {
      // Search for google_analist pattern. Used by
      // google-something-hackers.html
      if(stripos($this->contents,"google_analist") !== FALSE){
         //Critical
         $this->score += 100;
         $this->explain[] = "[google_analist]";
      }
      if(stripos($this->contents,"PhpReverseProxy") !== FALSE){
      	 $this->score += 100;
      	 $this->explain[] = "[php_reverse_proxy]";
      	 return;
      }
      if(stripos($this->contents,"ok creat file") !== FALSE AND stripos($this->contents,"ok del file"))
      {
      	$this->score += 100;
      	$this->explain[] = "[php_backdoor]";
      	return;
      }
     if(stripos($this->contents,"tool4spam.com") !== FALSE){
	     $this->score += 100;
         $this->explain[] = "[google_analist]";
      }
      if(stripos($this->contents,"tmp_god") !== FALSE AND stripos($this->contents,"GodSpy") !== FALSE
        AND stripos($this->contents,"makehide") !== FALSE
      ) {
        $this->score += 100;
        $this->explain[] = "[shell_script]";
      }
    // The second if is required because of a Joomla's com_users wording.
	if(stripos($this->contents, "Mass Mailer") !== FALSE AND stripos($this->contents,"Redirect to admin index if mass mailer") === FALSE)
	{
		$this->score +=100;
		$this->explain[] = "[mass_mailer]";
	}
   }


   private function global_rule_2()
   {
   	//Revslider file check.
	if($this->f->getFilename() == "wp-class-headers.php" OR $this->f->getFilename() == "class-wp-index.php"){
		//This file is used by Revslider hackers.
		$this->score += 100;
		$this->explain[] = "[revslider_files]";
	}

	if($this->f->getFilename() == "wp-options.php" OR $this->f->getFilename() == "ms-head.php"){
		if(stripos($this->contents,"move_uploaded_file") !== FALSE){
			$this->score += 100;
	                $this->explain[] = "[revslider_upload]";
		}
	}
		
	 if(stripos($this->contents,"/etc/passwd") !== FALSE){
         //Bad
         $this->score += 100;
         $this->explain[] = "[etc_passwd_keyword]";
      }
   }

   private function global_rule_3()
   {
    	if(stripos($this->contents,'preg_replace("/.*/e"') !== FALSE OR stripos($this->contents,'preg_replace("/.+/e"') !== FALSE){
    	   // Very bad.
    	   $this->score += 100;
    	   $this->explain[] = "[pregmatch_evaluate]";
    	}
    }

    private function global_rule_4()
    {
    	if(stripos($this->contents,'hacked by') !== FALSE){
    	    //Pretty much bad.. :)
    	    if($this->f->getFilename() != "class.smtp.php"){
    	        $this->score += 100;
    	        $this->explain[] = "[hacked_by_str]";
    	    }
    	}
    }

    private function global_rule_5()
    {
            if(stripos($this->contents,'wscandir') !== FALSE AND stripos($this->contents,'filesman') !== FALSE AND stripos($this->contents,'uploadfile') !== FALSE)
            {
                $this->score +=100;
                $this->explain[] = "[File Uploader]";
                return;
            }
            if(stripos($this->contents,'PHP_OS') !== FALSE AND !array_key_exists('php_os',$this->reg)){
                if(!in_array(md5_file($this->f->getRealPath()),
                array('c3d902f1007e54d1f95b268e4f9643d6','a392bff2e5d22b555bf1e5c098a3eda3','d1c8a277f0cc128b5610db721c70eabd')
        	    )){ 
            	    $this->score += 15;
            	    $this->explain[] = "[PHP_OS]";
            	    $this->reg['php_os'] = TRUE;
        	    }
        	}
        	if(stripos($this->contents,'extension_loaded') !== FALSE AND !array_key_exists('extension_loaded',$this->reg)){
        	    if(!in_array($this->f->getFilename(), array('php-brief.php','mootools-more.js','php.php','tokenizephp.js','simplepie.php'))){
            	    $this->score += 15;
            	    $this->explain[] = "[extension_loaded_keyword]";
            	    $this->reg['extension_loaded'] = TRUE;
        	    }
        	}
        	if(stripos($this->contents,'socket_create') !== FALSE AND !array_key_exists('socket_create',$this->reg)){
                    if(!in_array(md5_file($this->f->getRealPath()),
                    array('c3d902f1007e54d1f95b268e4f9643d6','a392bff2e5d22b555bf1e5c098a3eda3')
                    )){ 
                        $this->score += 15;
                        $this->explain[] = "[socket_create_keyword]";
            	        $this->reg['socket_create'] = TRUE;
                    }
                }
        	if(stripos($this->contents,'move_uploaded_file') !== FALSE AND !array_key_exists('move_upload',$this->reg)){
            	     if(!in_array($this->f->getFilename(), array('php-brief.php','mootools-more.js','php.php','tokenizephp.js'))){     
                        $this->score += 20;
                        $this->explain[] = "[upload_script]";
            	        $this->reg['move_upload'] = TRUE;
            	   }
            }

    	if(stripos($this->contents,'vpsp_version') !== FALSE){
    	    $this->score +=100;
    	    $this->explain[] = "[vpsp_proxy]";
    	}
    	
    	if(stripos($this->contents,'J3F1N') !== FALSE){
    	    $this->score +=100;
    	    $this->explain[] = "[j3f1n_mailer]";
    	}

	if(stripos($this->contents,'PHP Bulk Emailer') !== FALSE){
	    $this->score +=100;
	    $this->explain[] = "[bulk_emailer]";
	}
    
    	if(stripos($this->contents,'shmop.so') !== FALSE OR stripos($this->contents,'php_shmop.dll') !== FALSE){
    	    $this->score +=100;
    	    $this->explain[] = "[shmop_ext]";
    	}
    	if(stripos($this->contents,'edoced_46esab') !== FALSE){
    	    $this->score +=100;
    	    $this->explain[] = "[strrev_base64]";
    	}

	if(stripos($this->contents,'WSO_VERSION') !== FALSE){
	    $this->score +=100;
	    $this->explain[] = "[Shell_script]";
	}
    
    	if(stripos($this->contents, '"fro"+"mC"+"harC"+"o"+"de"') !== FALSE){
    	    $this->score +=100;
    	    $this->explain[] = "[Obfus_fromcharcode]";
    	}

	if(stripos($this->contents, 'PostMan Full') !== FALSE){
		$this->score +=100;
		$this->explain[] = "[Postman_mlr]";
	}
	if(stripos($this->contents, 'php_display') !== FALSE AND stripos($this->contents, 'error_404') !== FALSE AND stripos($this->contents, '@file_get_contents') !== FALSE){
		$this->score +=100;
		$this->explain[] = "[Remote_fetch]";
	}
	
	if(stripos($this->contents, "pagecr.html") !== FALSE){
		$this->score +=100;
		$this->explain[] = "[html_generator]";
	}

    }
    
    private function global_rule_6()
    {
    	if($this->f->getExtension() == "php"){
    		if(stripos($this->contents, "return base64_decode") !== FALSE 
    			AND stripos($this->contents, "eval(") !== FALSE
    			AND stripos($this->contents, "strlen(") !== FALSE
    			AND stripos($this->contents, "Array(") !== FALSE
    		) {
    			$this->score += 100;
    			$this->explain[] = "[mass_mailer]";
    		}
    		
    		if(stripos($this->contents, "\$numemails = count(\$allemails);") !== FALSE)
    		{
    			$this->score += 100;
    			$this->explain[] = "[mass_mailer]";
    		}
    		if(stripos($this->contents, '="base64_decode";return') !== FALSE
    		    AND stripos($this->contents, ".= isset(\$") !== FALSE
    		    AND stripos($this->contents, "strlen") !== FALSE
    		    ){
    		        $this->score += 100;
    		        $this->explain[] = "[php_mailer31]";
    		    }
    	}
    }


   private function rule_1($l){
      // We do not really want to check JS scripts where eval is rather common
      if($this->f->getExtension() == "js")
      {
      	return false;
      }
      // eval(anything here)ase64_decode regex search
      if(preg_match('/\beval\b\s*(.*)\(\s*base64_decode/i',$l))
      {
         //This is pretty obvious. Both eval and base64 are present one after
         //another.
         $this->score += 100;
         $this->explain[] = "[eval_base64]";
      } 
 
   }
   
   private function rule_2($l){
   		if($this->f->getExtension() == "php")
   		{
   			if(stripos($l,"array_diff_ukey") !== FALSE AND stripos($l,"request") !== FALSE)
   			{
   				$this->score += 100;
   				$this->explain[] = "[array_dif|request]";
   				return true;
   			}
   			
   			if(stripos($l,"mail(") !== FALSE AND stripos($l,'$_POST') !== FALSE AND stripos($l,'stripslashes') !== FALSE)
   			{
   				$this->score += 100;
   				$this->explain[] = "[mail|post]";
   				return true;
   			}
   		}
   }

   private function rule_7($l){
      
      // We do not really want to check JS scripts where eval is rather common
      if($this->f->getExtension() == "js")
      {
      	return false;
      }
      // Search for eval($_POST or eval($_GET) or request/cookie/etc
      if(preg_match('/\beval\b\s*(.*)\(\s*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SERVER)/i',$l)){
         //This is critical.
         $this->score += 100;
         $this->explain[] = "[eval|sys_globals]";
      }
      // Search for system followed by killall, crontab, ps or cat whole words only.
      if(preg_match('/\b(system|exec)\b\s*(.*)\(\s*.*(\bkillall\b|\bcrontab\b|\bcat\b)/i',$l)){
         //This is critical.
         $this->score += 100;
         $this->explain[] = "[exec|cmd_command]";
      }
   }

   private function rule_3($l){
	//Search for eval and check if certain conditions are met.
	//skip if file is not a .php file
    if($this->f->getExtension() == "php"){ 
    	if(stripos($l, 'eval') !== FALSE){
    	    //Shell script with obfuscated entries.
    	    if(stripos($l,'$__') !== FALSE){
        		$this->score += 100;
        		$this->explain[] = "[eval_obfusc]";
    	    }
    	}
    }
   }

   private function rule_4($l){
      // Search for script document.write followed by an iframe
      if(in_array($this->f->getFilename(), array('tinymce.min.js','easyXDM.debug.js','tinymce.js','tiny_mce.js','codemirror.js','mootools.js','customize-controls.min.js')))
	return;
      if($this->f->getExtension() == "php") 
	{
      if(preg_match('/script\s*(.*)document\.write\s*(.*)iframe/i',$l)){
         //Pretty much critical as well.
         $this->score += 100;
         $this->explain[] = "[scr+doc.write+ifrm]";
      }
	}
   }
   
   private function rule_6($l){
        if(stripos($l,'visibility') !== FALSE AND stripos($l,'echo') !== FALSE AND stripos($l,'iframe') !== FALSE)
        {
            //Contains echo, iframe and visibility keywords in a single line.
            $this->score +=100;
            $this->explain[] = "[iframe+visib]";
        }
        if(stripos($l, "strtoupper(") !== FALSE AND stripos($l, "eval(") !== FALSE)
        {
                $this->score +=100;
                $this->explain[] = "[strtoupper_eval]";
        }
   }

   private function rule_5($l){
   	
   		if(stripos($l,"stream_context_create") !== FALSE AND stripos($l,"stream_socket_client") !== FALSE AND stripos($l,"base64_decode") !== FALSE)
   		{
   			if($this->f->getExtension() == "php"){
   			    $this->score +=100;
   			    $this->explain[] = "[socket+base64]";
   			return;
   			}
   		}
   		//TODO: change this to regex to check whole words only.
   		if(stripos($l, "porn") !== FALSE AND stripos($l, "sex") !== FALSE)
   		{
   			$this->score += 100;
   			$this->explain[] = "[porn_sex_keys]";
   			return;
   		}

    	//Very clever tmp/analog spam inclusion code.
    	if(stripos($l,"@require_once") !== FALSE AND stripos($l,"tmp/analog") !== FALSE){
    	    $this->score +=100;
    	    $this->explain[] = "[joomla_tmp/analog]";
    	}
    
    	if(!isset($this->reg['long_line']) AND strlen($l) > 700){
            //Not really critical but suspicious.
        	if(stripos($l,'eval(') !== FALSE AND $this->f->getExtension() != "js" AND $this->f->getExtension() != "ini"){
        	    //This is rather general. We need to exclude some well know files which are NOT malicious.
            		if($this->f->getExtension() != "meta" AND $this->f->getExtension() != "js" AND $this->f->getExtension() != "json"){
					$this->score +=50;
            		$this->explain[] = "[eval+long_line]";
        	    }
        	}

        	//Long lines are normal for most files but PHP.
            if($this->f->getExtension() == "php"){
			//Additional checks for keywords in such a long line
                if(stripos($l,'ini_set') !== FALSE){
            	    $this->score +=15;
            	    $this->explain[] = "[+ini_set]";
            	}
            	if(stripos($l,'md5') !== FALSE){
            	    $this->score +=15;
            	    $this->explain[] = "[+md5]";
            	}
				if(stripos($l,'$globals')){
				    $this->score += 50;
				    $this->explain[] = "[+globals]";
				}
				if(stripos($l,'urldecode') !== FALSE){
        	        $this->score +=25;
        	        $this->explain[] = "[+urldecode]";
        	    }
            	if(stripos($l,'mail') !== FALSE){
            	    $this->score +=25;
            	    $this->explain[] = "[+mail]";
            	}
				if(stripos($l,'preg_replace') !== FALSE){
					$this->score+=50;
					$this->explain[] = "[preg_repl_long]";
				}
                 $this->score += 50;
                 if(empty($this->explain)){
                 	$this->explain[] = "[too_long_line]";
                }
                //TODO: Add a space char count check.
                 $this->reg['long_line'] = TRUE;
	    }
      }
   }
}

class AppFocus {
    
    public $app_version; //String
    public $app_hashes; //Array
    public $app_name; //String
    public $app_hashes_update_server; //String
    
    public function fetch_app_hashes(){
        $opts = array(
          'http'=>array(
            'method'=>"GET",
            'header'=>"Accept-language: en\r\n" .
                      "User-agent: HackSearch GitHub Version\r\n"
          )
        );
        $context = stream_context_create($opts);
        $ret = file_get_contents($this->app_hashes_update_server . $this->app_version . ".txt",FALSE,$context);
        $this->app_hashes = unserialize($ret);
        if(is_array($this->app_hashes) AND count($this->app_hashes) > 0){
            return true;
        } else {
            return false;
        }
    }
    
    public function hash_match($filename,$hash){
        if(isset($this->app_hashes[$filename]))
        {
            if($this->app_hashes[$filename] == $hash){
                return true;
            } else {
                return false;
            }
        }
        return false; // Not found in the hash database
    }
}

class WordpressFocus extends AppFocus {
    
    public $app_version;
    public $app_hashes = array();
    public $app_name = "WordPress";
    public $app_hashes_update_server = "http://www.phpfire.net/hacksearch/wordpress/"; //WITH A TRAILING SLASH
    
    public function get_version()
    {
        $version = "0.0";
        if(file_exists('wp-includes/version.php'))
        {
            $contents = file('wp-includes/version.php', FILE_IGNORE_NEW_LINES  |FILE_SKIP_EMPTY_LINES);
              foreach($contents as $line)
              {
                  if(stripos($line,'$wp_version =') !== FALSE)
                  {
                      preg_match('/\d\.\d+(\.\d)?/i',$line,$matches);
                      if(count($matches) > 0)
                      {
                          $version = $matches[0];
                      }
                  }
              }
        }
        
        if($version == "0.0")
        {
            return false;
        } else {
            $this->app_version = $version;
            return true;
        }
    }
    
}

class JoomlaFocus extends AppFocus {
    public $app_version;
    public $app_hashes = array();
    public $app_name = "Joomla";
    public $app_hashes_update_server = "http://www.phpfire.net/hacksearch/joomla/"; //WITH A TRAILING SLASH
    
    public function get_version()
    {
        $major = 0;
        $minor = 0;
        
        $found = false;
        if(file_exists('libraries/cms/version/version.php'))
        {
            $contents = file('libraries/cms/version/version.php', FILE_IGNORE_NEW_LINES  |FILE_SKIP_EMPTY_LINES);
              foreach($contents as $line)
              {
                  if(stripos($line,'public $RELEASE =') !== FALSE)
                  {
                      preg_match('/\d\.\d/',$line,$matches);
                      if(count($matches) > 0)
                      {
                          $major = $matches[0];
                      }
                  }
                  if(stripos($line,'$DEV_LEVEL =') !== FALSE)
                  {
                      preg_match('/\d/',$line,$matches);
                      if(count($matches) > 0)
                      {
                          $minor = $matches[0];
                          $found = true;
                      }
                  }
              }
        }
        if($major != 0 AND $found)
        {
            $this->app_version = $major . "." . $minor;
            return true;
        } else {
            return false;
        }
    }
}

class HackSearch_Version_Result 
{
    public $appName;
    public $appVersion;
    public $location;
    
    public function __construct($appName,$appVersion,$location)
    {
        $this->appName = $appName;
        $this->appVersion = $appVersion;
        $this->location = $location;
    }
}

class HackSearch_Versions 
{
    
    private $app_files = array(
        'WordPress' => '/wp-includes/version.php',
        'Joomla' => '/libraries/cms/version/version.php',
        'Magento1' => '/app/Mage.php',
        'Magento2' => '/vendor/magento/magento2-base/composer.json',
        'Drupal8' => '/core/modules/dblog/dblog.info.yml',
        'Drupal6or7' => '/modules/dblog/dblog.info',
        'phpBB' => '/includes/constants.php',
        'Gallery2' => '/modules/core/module.inc',
        'Gallery3' => '/modules/gallery/helpers/gallery.php',
        'MediaWiki' => '/includes/DefaultSettings.php',
        'OpenCart' => '/admin/index.php',
        'PrestaShop' => '/config/settings.inc.php',
        'PrestaShop17' => '/config/autoload.php',
        'osCommerce' => '/admin/includes/application_top.php'
    );
    
    public $results = array();

    public function is_version_file($path)
    {
        foreach($this->app_files as $k=>$v)
        {
            if($this->endswith($path, $v))
            {
                return $k;
            }
        }
        //If none of the files match..
        return "";
    }
    
    public function check_app_version($filename)
    {
        $app_name = $this->is_version_file($filename);
        if($app_name == "")
        {
            //Something went wrong. This is not the version file we are looking for...
            return false;
        }
        
        //Determine the version of the application now.
        $method = 'check_'.$app_name.'_version';
        if(!method_exists($this, $method))
        {
            //There is no method for this app.
            return false;
        }
        
        return $this->$method($filename);
        
    }
    
    private function check_WordPress_version($filename)
    {
        $f=file($filename, FILE_SKIP_EMPTY_LINES);
        $matches = array();
        foreach($f as $line)
        {
            if(stripos($line, 'wp_version = ') !== false)
            {
                preg_match('/\d+\.\d+/',$line,$matches);
            }
        }
        if(isset($matches[0]) AND strlen($matches[0]) > 0)
        {
            $path_parts = @explode($this->app_files['WordPress'],$filename);
            $this->results[] = new HackSearch_Version_Result('WordPress',$matches[0],$path_parts[0]);
        }
    }
    
    private function check_PrestaShop_version($filename)
    {
        $f=file($filename, FILE_SKIP_EMPTY_LINES);
        $matches = array();
        foreach($f as $line)
        {
            if(stripos($line, "define('_PS_VERSION_', '") !== false)
            {
                preg_match('/\d+\.\d*\.*\d*\.*\d*/',$line,$matches);
            }
        }
        if(isset($matches[0]) AND strlen($matches[0]) > 0)
        {
            $path_parts = @explode($this->app_files['PrestaShop'],$filename);
            $this->results[] = new HackSearch_Version_Result('PrestaShop',$matches[0],$path_parts[0]);
        }
    }
    
    private function check_PrestaShop17_version($filename)
    {
        $f=file($filename, FILE_SKIP_EMPTY_LINES);
        $matches = array();
        foreach($f as $line)
        {
            if(stripos($line, "define('_PS_VERSION_', '") !== false)
            {
                preg_match('/\d+\.\d*\.*\d*\.*\d*/',$line,$matches);
            }
        }
        if(isset($matches[0]) AND strlen($matches[0]) > 0)
        {
            $path_parts = @explode($this->app_files['PrestaShop17'],$filename);
            $this->results[] = new HackSearch_Version_Result('PrestaShop-1.7.x',$matches[0],$path_parts[0]);
        }
    }
    
    
    private function check_OpenCart_version($filename)
    {
        $f=file($filename, FILE_SKIP_EMPTY_LINES);
        $matches = array();
        foreach($f as $line)
        {
            if(stripos($line, "define('VERSION', '") !== false)
            {
                preg_match('/\d+\.\d*\.*\d*\.*\d*/',$line,$matches);
            }
        }
        if(isset($matches[0]) AND strlen($matches[0]) > 0)
        {
            $path_parts = @explode($this->app_files['OpenCart'],$filename);
            $this->results[] = new HackSearch_Version_Result('OpenCart',$matches[0],$path_parts[0]);
        }
    }
    
    private function check_Drupal8_version($filename)
    {
        $f=file($filename, FILE_SKIP_EMPTY_LINES);
        $matches = array();
        foreach($f as $line)
        {
            if(stripos($line, 'version: ') !== false)
            {
                preg_match('/\d+\.\d*\.*\d*/',$line,$matches);
            }
        }
        if(isset($matches[0]) AND strlen($matches[0]) > 0)
        {
            $path_parts = @explode($this->app_files['Drupal8'],$filename);
            $this->results[] = new HackSearch_Version_Result('Drupal-8.x',$matches[0],$path_parts[0]);
        }
    }
    
    private function check_Drupal6or7_version($filename)
    {
        $f=file($filename, FILE_SKIP_EMPTY_LINES);
        $matches = array();
        foreach($f as $line)
        {
            if(stripos($line, 'version: ') !== false)
            {
                preg_match('/\d+\.\d*\.*\d*/',$line,$matches);
            }
        }
        if(isset($matches[0]) AND strlen($matches[0]) > 0)
        {
            $path_parts = @explode($this->app_files['Drupal6or7'],$filename);
            $this->results[] = new HackSearch_Version_Result('Drupal-6.x/7.x',$matches[0],$path_parts[0]);
        }
    }
    
    private function check_osCommerce_version($filename)
    {
        //We left the detection filename to be the application_top, so we can filter most apps.
        //The actual version of the app however can be found in includes/version.php file.
        $path_parts = @explode($this->app_files['osCommerce'],$filename);
        $matches = array();
        if(file_exists($path_parts[0]. "/includes/version.php"))
        {
            $matches[] = file_get_contents($path_parts[0]. "/includes/version.php");
        } else {
            //We fall back to the original application top check.
            $f=file($filename, FILE_SKIP_EMPTY_LINES);
            foreach($f as $line)
            {
                if(stripos($line, "define('PROJECT_VERSION'") !== false)
                {
                    preg_match('/\d+\.*\d*\.*\d*/',$line,$matches);
                }
            }
        }
        if(isset($matches[0]) AND strlen($matches[0]) > 0)
        {
            $this->results[] = new HackSearch_Version_Result('OsCommerce',$matches[0],$path_parts[0]);
        }
    }
    
    private function check_phpBB_version($filename)
    {
        $f=file($filename, FILE_SKIP_EMPTY_LINES);
        $matches = array();
        foreach($f as $line)
        {
            if(stripos($line, "define('PHPBB_VERSION', '") !== false)
            {
                preg_match('/\d+\.\d*\.*\d*/',$line,$matches);
            }
        }
        if(isset($matches[0]) AND strlen($matches[0]) > 0)
        {
            $path_parts = @explode($this->app_files['phpBB'],$filename);
            $this->results[] = new HackSearch_Version_Result('phpBB-3x',$matches[0],$path_parts[0]);
        }
    }
    
    private function check_Gallery2_version($filename)
    {
        $f=file($filename, FILE_SKIP_EMPTY_LINES);
        $matches = array();
        foreach($f as $line)
        {
            if(stripos($line, "this->setGalleryVersion(") !== false)
            {
                preg_match('/\d+\.\d*\.*\d*/',$line,$matches);
            }
        }
        if(isset($matches[0]) AND strlen($matches[0]) > 0)
        {
            $path_parts = @explode($this->app_files['Gallery2'],$filename);
            $this->results[] = new HackSearch_Version_Result('Gallery-2x',$matches[0],$path_parts[0]);
        }
    }
    
    private function check_Gallery3_version($filename)
    {
        $f=file($filename, FILE_SKIP_EMPTY_LINES);
        $matches = array();
        foreach($f as $line)
        {
            if(stripos($line, "const VERSION =") !== false)
            {
                preg_match('/\d+\.\d*\.*\d*/',$line,$matches);
            }
        }
        if(isset($matches[0]) AND strlen($matches[0]) > 0)
        {
            $path_parts = @explode($this->app_files['Gallery3'],$filename);
            $this->results[] = new HackSearch_Version_Result('Gallery-3x',$matches[0],$path_parts[0]);
        }
    }
    
    private function check_MediaWiki_version($filename)
    {
        $f=file($filename, FILE_SKIP_EMPTY_LINES);
        $matches = array();
        foreach($f as $line)
        {
            if(stripos($line, "wgVersion = '") !== false)
            {
                preg_match('/\d+\.\d*\.*\d*/',$line,$matches);
            }
        }
        if(isset($matches[0]) AND strlen($matches[0]) > 0)
        {
            $path_parts = @explode($this->app_files['MediaWiki'],$filename);
            $this->results[] = new HackSearch_Version_Result('MediaWiki',$matches[0],$path_parts[0]);
        }
    }
    
    private function check_Magento2_version($filename)
    {
        $f=file($filename, FILE_SKIP_EMPTY_LINES);
        $matches = array();
        foreach($f as $line)
        {
            if(stripos($line, '"version": "') !== false)
            {
                preg_match('/\d+\.\d*\.*\d*/',$line,$matches);
            }
        }
        if(isset($matches[0]) AND strlen($matches[0]) > 0)
        {
            $path_parts = @explode($this->app_files['Magento2'],$filename);
            $this->results[] = new HackSearch_Version_Result('Magento 2.x',$matches[0],$path_parts[0]);
        }
    }
    
    private function check_Magento1_version($filename)
    {
        $f=file($filename, FILE_SKIP_EMPTY_LINES);
        $major = array();
        $minor = array();
        $revision = array();
        foreach($f as $line)
        {
            if(stripos($line, "'major'     => '1") !== false)
            {
                $major[] = "1";
            }
            if(stripos($line, "'minor'     => '") !== false)
            {
                preg_match('/\d+/',$line,$minor);
            }
            if(stripos($line, "'revision'     => '") !== false)
            {
                preg_match('/\d+/',$line,$revision);
            }
        }
        if(isset($matches[0]) AND strlen($matches[0]) > 0)
        {
            $path_parts = @explode($this->app_files['Magento2'],$filename);
            $this->results[] = new HackSearch_Version_Result('Magento 2.x',$major[0] . ".".$minor[0].".".$revision[0],$path_parts[0]);
        }
    }
    
    private function check_Joomla_version($filename)
    {
        $f=file($filename, FILE_SKIP_EMPTY_LINES);
        $matches_major = array();
        $matches_minor = array();
        foreach($f as $line)
        {
            //Get the Major version (2+ digits)
            if(stripos($line, 'const RELEASE =') !== false)
            {
                preg_match('/\d+\.\d+/',$line,$matches_major);
            }
            //Get the minor version (1+ digit)
            if(stripos($line, 'const DEV_LEVEL =') !== false)
            {
                preg_match('/\d+/',$line,$matches_minor);
            }
        }
        if(isset($matches_major[0]) AND isset($matches_minor[0]))
        {
            $path_parts = @explode($this->app_files['Joomla'],$filename);
            $this->results[] = new HackSearch_Version_Result('Joomla',$matches_major[0] . "." .$matches_minor[0],$path_parts[0]);
        }
        
    }
    
    public function endswith($string, $test) {
        $strlen = strlen($string);
        $testlen = strlen($test);
        if ($testlen > $strlen) return false;
        return substr_compare($string, $test, $strlen - $testlen, $testlen) === 0;
    }
    
    
}

/* Config Class */

class HackSearch_Config 
{
    public $caller_dir = "./";
    public $target_dir = "./";
    
    public $do_malware_scan = true; // By default, we should scan files for malware
    
    public $quiet = false;
    public $buffered = false;
    public $output = "standard";
    public $output_file = "hs.out";
    public $output_format = "txt";
    public $show_details = true;
    
    public $update_server = "http://phpfire.net/hacksearch/definitions.php";
    public $md5_server = "http://phpfire.net/hacksearch/md5s/index.html";
    public $excludes_server = "http://phpfire.net/hacksearch/falsepositive/index.html";
	public $hs_version = "2.3.0";
	
	public $appfocus;
	public $app_focused_run = false;
	public $afo; // App focused object. An instance of the app focus class.
	
    
    public function __construct()
    {
        global $options;
        $this->caller_dir = getcwd();
        
        if(isset($options['target']))
        {
            $this->target_dir = $options['target'];
        } else {
            $this->target_dir = $this->caller_dir;
        }
        
        if(isset($options['no-malware-scan']))
        {
            $this->do_malware_scan = false;
        }
        
        if(!@chdir($this->target_dir))
        {
            die("Cannot change directory to: ".$this->target_dir);
        }
        
        //Quiet please?
        if(isset($options['q']) AND !$options['q'])
        {
            $this->quiet = true;
        }
        
        //Output direction.
        if(isset($options['o']))
        {
            $this->quiet = true;
            $this->output_file = $options['o'];
            $this->output = "file";
        }
        
        if(isset($options['s']))
        {
            $this->show_details = false;
        }
        
        if(isset($options['appfocus']) and strlen($options['appfocus']) > 0)
        {
            $this->appfocus = $options['appfocus'];
            $this->app_focused_run = true;
        }
        
        if(isset($options['f']))
        {
            switch($options['f'])
            {
                case "txt":
                    $this->output_format = "txt";
                    break;
                case "html":
                    $this->output_format = "html";
                    break;
                case "xml":
                    $this->output_format = "xml";
                    break;
                case "json":
                    $this->output_format = "json";
                    break;
                case "serialize":
                    $this->output_format = "serialize";
                    break;
                default:
                    $this->output_format = "txt";
            }
        }
    }
    
}

/* Shell Colors Class */

class HackSearch_Colors {
	private $foreground_colors = array();
	private $background_colors = array();
	private $cfg;
 
	public function __construct($cfg) {
	    // Set up shell colors
	    $this->cfg = $cfg;
	    $this->foreground_colors['black'] = '0;30';
	    $this->foreground_colors['dark_gray'] = '1;30';
	    $this->foreground_colors['blue'] = '0;34';
	    $this->foreground_colors['light_blue'] = '1;34';
	    $this->foreground_colors['green'] = '0;32';
	    $this->foreground_colors['light_green'] = '1;32';
	    $this->foreground_colors['cyan'] = '0;36';
	    $this->foreground_colors['light_cyan'] = '1;36';
	    $this->foreground_colors['red'] = '0;31';
	    $this->foreground_colors['light_red'] = '1;31';
	    $this->foreground_colors['purple'] = '0;35';
	    $this->foreground_colors['light_purple'] = '1;35';
	    $this->foreground_colors['brown'] = '0;33';
	    $this->foreground_colors['yellow'] = '1;33';
	    $this->foreground_colors['light_gray'] = '0;37';
	    $this->foreground_colors['white'] = '1;37';

 
	    $this->background_colors['black'] = '40';
	    $this->background_colors['red'] = '41';
	    $this->background_colors['green'] = '42';
	    $this->background_colors['yellow'] = '43';
	    $this->background_colors['blue'] = '44';
	    $this->background_colors['magenta'] = '45';
	    $this->background_colors['cyan'] = '46';
	    $this->background_colors['light_gray'] = '47';
	}
 
	// Returns colored string
	public function getColoredString($string, $foreground_color = null, $background_color = null) {
	    $colored_string = "";
	    if($this->cfg->output !== "standard")
	    { return $string; }  //No coloring for output different than standard output 
	    // Check if given foreground color found
	    if (isset($this->foreground_colors[$foreground_color])) {
		$colored_string .= "\033[" . $this->foreground_colors[$foreground_color] . "m";
	    }
	    // Check if given background color found
	    if (isset($this->background_colors[$background_color])) {
		$colored_string .= "\033[" . $this->background_colors[$background_color] . "m";
	    }
 
	    // Add string and end coloring
	    $colored_string .=  $string . "\033[0m";
 
	    return $colored_string;
	}
 
	// Returns all foreground color names
	public function getForegroundColors() {
	    return array_keys($this->foreground_colors);
	}
 
	// Returns all background color names
	public function getBackgroundColors() {
	    return array_keys($this->background_colors);
	}
}

/* Output Class */

class HackSearch_Output 
{
    private $cfg;
    private $colors;
    
    public $output;
    
    
    public function __construct($cfg, $colors)
    {
        $this->cfg = $cfg;
        $this->colors = $colors;
    }
    
    public function e($string, $n = 1, $f = NULL, $b = NULL){
        if($n){
            $string = $string . "\n";
        }
        echo $this->colors->getColoredString($string,$f,$b);
    }
    
    public function print_banner()
    {
        if(!$this->cfg->quiet)
        {
            $this->e('##############################################',1,'cyan');
            $this->e('## PHP Hack Search v2.3.0                   ##',1,'cyan');
            $this->e('## Author: Valeri Markov                    ##',1,'cyan');
            $this->e('## URL: http://www.phpfire.net/             ##',1,'cyan');
            $this->e('## License: MIT LICENSE, see --license      ##',1,'cyan');
            $this->e('## (C) Copyright 2012-2017 Valeri Markov    ##',1,'cyan');
            $this->e('##############################################',1,'cyan');
        }
    }
    
    public function set_results($scanned,$hits,$infected,$appversions = NULL)
    {
        switch($this->cfg->output)
        {
            case "standard":
                $this->standard_results($scanned,$hits,$infected,$appversions);
                break;
            case "file":
                $this->to_file($scanned,$hits,$infected,$appversions);
                break;
            default:
                $this->standard_results($scanned,$hits,$infected,$appversions);
        }
    }
    
    public function standard_results($scanned,$hits,$infected,$appversions=null)
    {
        if(!$this->cfg->quiet)
        {
            $this->e('');
            $this->e('Scan completed on: '.date("Y-m-d H:i:s", time()),1,'white');
            $this->e('');
            $this->e('Results:',1,'white');   
        }
        
        $this->format_infected($infected,$appversions);
        
    }
    
    public function to_file($scanned,$hits,$infected)
    {
        ob_start();
        $this->format_infected($infected);
        $out = ob_get_clean();
        chdir($this->cfg->caller_dir); //Return back to our directory..
        if(!file_put_contents(trim($this->cfg->output_file),$out)){
            echo "Cannot write to file" . $this->cfg->output_file . ". Dumping data here...\n".$out;
        }
        
    }
    
    public function format_infected($infected,$appversions)
    {
        //As txt format
        if($this->cfg->output_format == "txt")
        {
            foreach($infected as $f=>$data)
            {
               $explain = "";
               if(is_array($data['explain'])){
                	foreach($data['explain'] as $l){
                	    $explain .= $l;
                	}
                } else {
            	    $explain = $data['explain'];
                }
                if($this->cfg->show_details)
                {
                   $this->e("[".$data['score']."]\t",0,"cyan"); 
                   $this->e($explain,0);
                }
                
                if($this->cfg->show_details)
                {
                    if(strlen($explain) > 15){
                        $this->e("\t".$f,1,'white');
                    } else {
                       $this->e("\t\t".$f,1,'white'); 
                    }
                } else {
                        $this->e($f,1,'white');
                }
                /*
                if($this->cfg->show_details){
                    $this->e($explain);
                }
                */
            }
            
            if($appversions != null)
            {
                $this->e("");
                $this->e("Applications found:",1,'white');
                $this->e("");
                
                foreach($appversions->results as $result)
                {
                   $this->e($result->appName,0,"white");
                   $this->e("\t".$result->appVersion,0,'cyan');
                   $this->e("\t".$result->location,1,'green');
                }
                
            } 
            return;
        }
        
        //As XML
        if($this->cfg->output_format == "xml")
        {
            $this->e("<results>");
            foreach($infected as $f=>$data)
            {
                
                $this->e("<result>");
                $this->e("\t<file>".$f."</file>");
                if(is_array($data['explain']))
                {
                    foreach($data['explain'] as $l){
                	    $this->e("\t<reason>".$l."</reason>");
                	}
                } else {
                    $this->e("\t<reason>".$l."</reason>");
                }
                $this->e("</result>");
            }
            $this->e("</results>");
            return;
        }
        
        //As JSON
        if($this->cfg->output_format == "json")
        {
            $this->e(json_encode($infected));
            $this->e(json_encode($appversions->results));
            return;
        }
        
        //As PHP Serialize
        if($this->cfg->output_format == "serialize")
        {
            $this->e(serialize($infected));
            $this->e(serialize($appversions->results));
            return;
        }
    }
    
    public function print_help()
    {
        $this->e("HackSearch by Valeri Markov.",0);
        $this->e("Scan files for malicious code.",1);
        $this->e("Usage: php hacksearch.php [OPTIONS]",1,'white');
        $this->e("");
        
        $this->e("  -o <file> \t\t",0,'cyan');
        $this->e("Redirect the output to a <file>.",1,'white');
        
        $this->e("  -s \t\t\t",0,'cyan');
        $this->e("Enable short mode. Does not print details on why the file is being detected as malicious.",1,'white');
        
        $this->e("  -f <format> \t\t",0,'cyan');
        $this->e("Set the output format. Available options are: txt (default),xml,json,php-serialize",1,'white');
        
        $this->e("  -q \t\t\t",0,'cyan');
        $this->e("Quiet mode. Does not print anything until the end of the script.",1,'white');
        
        $this->e("");
        $this->e("  --target \t\t\t",0,'cyan');
        $this->e("Set the folder to scan. By default it is the current working directory.",1,'white');
        
        $this->e("  --appfocus \t\t\t",0,'cyan');
        $this->e("Set the application focus. Available options are WordPress and Joomla.",1,'white');
        
        $this->e("  --help \t\t\t",0,'cyan');
        $this->e("Show this screen.",1,'white');
        
        $this->e("  --version \t\t\t",0,'cyan');
        $this->e("Display the version of the script.",1,'white');
        
        $this->e("  --license \t\t\t",0,'cyan');
        $this->e("Display the license text.",1,'white');
        $this->e("");
    }
    
    public function print_version()
    {
        $this->e("HackSearch v".HS_VERSION." by Valeri Markov <val@phpfire.net>");
    }
    
    public function print_license()
    {
        $this->e("");
        $this->e("License",1,'white');
        $license = <<<EOT
MIT License

Copyright (c) 2017 Valeri Markov http://www.phpfire.net/

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
EOT;
    $this->e($license);
        
    }
}

/* The updater function */
function fetch_rules($source_url, $isMD5 = FALSE)
{
    $opts = array(
      'http'=>array(
        'method'=>"GET",
        'header'=>"Accept-language: en\r\n" .
                  "User-agent: HackSearch GitHub Version\r\n"
      )
    );
    $context = stream_context_create($opts);
    $ret = file_get_contents($source_url,FALSE,$context);
    return @unserialize($ret);
}

/***********************************************************************************/
/**************************** Fun starts here **************************************/
/***********************************************************************************/


    $config = new HackSearch_Config();
    $colors = new HackSearch_Colors($config);
    $output = new HackSearch_Output($config,$colors);
    $appversions = new HackSearch_Versions();
    
    if(isset($options['help']))
    {
        die($output->print_help());
    }
    
    if(isset($options['version']))
    {
        die($output->print_version());
    }
    
    if(isset($options['license']))
    {
        die($output->print_license());
    }
    
    /* Show the banner */
    $output->print_banner();
    
    /* Download scan rules */
    if(!$config->quiet)
    {
        $output->e("\n[*]",0,'green');
        $output->e(' Updating malware definitions',1,'white');
    }
    $scanner = new FileScanner();
    
    /* Download MD5 Hashes */
    if(!$config->quiet)
    {
        $output->e("[*]",0,'green');
        $output->e(' Updating MD5 hashes',0,'white');
    }
    $md5s = fetch_rules($config->md5_server,TRUE);
    if(!$config->quiet)
    {
        $output->e(' (Found: '.count($md5s).')',1,'white');
    }

	if(!$config->quiet)
	{
		$output->e("[*]",0,'green');
		$output->e(' Excluding false positives',0,'white');
	}
	$false_positives = fetch_rules($config->excludes_server,true);

	if(!$config->quiet)
    {
        $output->e(' (Found: '.count($false_positives).')',1,'white');
    }
    
    /* Is there any App focus enabled? */
    if($config->app_focused_run)
    {
        if(class_exists(ucfirst(strtolower($config->appfocus))."Focus"))
        {
            $class = ucfirst(strtolower($config->appfocus))."Focus";
            $config->afo = new $class();
            if(!$config->afo->get_version())
            {
                if(!$config->quiet)
                {
                    $output->e("[*]",0,'red');
                    $output->e(' Appfocus: cannot determine application version.',0,'white');
                }
                $config->app_focused_run = false;
            
                if(!$config->quiet)
                {
                    $output->e("[*]",0,'red');
                    $output->e(' Appfocus: is now disabled.',1,'white');
                }
            } else {
                if(!$config->afo->fetch_app_hashes())
                {
                    if(!$config->quiet)
                    {
                        $output->e("[*]",0,'red');
                        $output->e(' Appfocus: cannot download specific version hashes.',0,'white');
                    }
                
                    $config->app_focused_run = false;
            
                    if(!$config->quiet)
                    {                   
                        $output->e("[*]",0,'red');
                        $output->e(' Appfocus: is now disabled.',1,'white');
                    }
                } else {
                    if(!$config->quiet)
                    {
                        $output->e("[*]",0,'green');
		                $output->e(' AppFocus enabled. '.$config->afo->app_name." version ".$config->afo->app_version,1,'white');
                    }
                }
            }
        } else {
            if(!$config->quiet)
            {
                $output->e("[*]",0,'red');
                $output->e(' Appfocus: passed unknown application parameter.',0,'white');
            }
            
            $config->app_focused_run = false;
            
            if(!$config->quiet)
            {        
                $output->e("[*]",0,'red');
                $output->e(' Appfocus: is now disabled.',0,'white');
            }
        }
    }
   
 
    /* Print the start time */
    $config->start_time = time();
    if(!$config->quiet)
    {
        $output->e('');
        $output->e('Scan started on: '.date("Y-m-d H:i:s", time()),1,'white');
        $output->e("Files:                              ",0,'white');  // 30 characters of padding at the end
    }

    /* The main iterator and some runtime variables */
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator('./'));
    $infected = array();
    $scanned = 0;
    $hits = 0;
        
    /* And off we go into the loop */
    while($it->valid()) {
        try{    
            if (!$it->isDot() AND !$it->isDir()) {
                   // First check the MD5 sum of the file.
                   // Matched files will not be opened for reading to save time.
                   // Only scan files bigger than 0 bytes and less than 2MB
					$fmd5 = md5_file($it->key());
					
					//Check if this is a version file.
					if(strlen($appversions->is_version_file($it->getRealPath())) > 0)
					{
					    $appversions->check_app_version($it->getRealPath());
					}
					
					// Check if AppFocus has been defined and process the file first.
					if($config->app_focused_run)
					{
					    if(!$config->afo->hash_match($it->key(),$fmd5)){
					        $hits++;
					        $infected[$it->getRealPath()] = array('explain' => '[modified_core_file]','score' => 100);
					        $it->next();
					        continue;
					    }
					}
					
                    if($config->do_malware_scan AND $it->getSize() > 0 AND $it->getSize() < 2048576 ){ 
						if(in_array($fmd5, $false_positives))
						{
							$it->next();
							continue;
						}
                        if(in_array($fmd5,$md5s)){
                           //md5 hit
                           $hits++;
            		       $infected[$it->getRealPath()] = array('explain' => '[md5sum_match]','score' => 100);
                        } else {
                           $s = new FileScanner();
                           $s->scan($it);
                           if($s->score > 99){
                              $infected[$it->getRealPath()]= array(
                                    'score' => $s->score,
                                    'explain' => $s->explain
                              );
                              //Increase the hit rate by one.
            		          $hits++;
                            }
                        }
                   }
                   //Increase the total scanned files by one.
                   $scanned++;
                   //Update the status to user stdout.
                   if(!$config->quiet){
                   	    echo "\033[29D";      // Move 29 characters backwards
                   	    echo str_pad($scanned . ' Hits: '.$hits, 29);    // Output is always 29 characters long
                   }
            }
        } catch(Exception $e){
    	/* TODO: We should really catch this exception, rather than just ignore it... */
        }
        //Next item...
        $it->next();
    }
    
    $config->complete_time = time();
    $output->set_results($scanned,$hits,$infected,$appversions);

    //Send success signal..
    exit(0);