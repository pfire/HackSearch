# HackSearch

## v2.3.0 

HackSearch is a malware search tool written in PHP. It is mainly focused on detecting compromised/hacked files in PHP web based applications, such as Joomla, WordPress, Magento, etc.

### Requirements
* PHP v 5.3.10+
* Ability to run as CLI (i.e. SSH/Crontab/etc)
* Linux / Unix based server

### Common Usage

The most common way to run the program is by downloading it and passing it to the PHP CLI. The following command will do just that in your current directory:

```
curl -sS https://raw.githubusercontent.com/pfire/HackSearch/master/hacksearch.php | php-cli
```
Depending on your setup, you might want to change *php-cli* to just *php*. The above command will run the HackSearch script with its default settings. HackSearch supports wide variety of command line options. For a full list of them, please use the --help option. Some of them are listed below.

### How to change the scan target directory

In order to scan a folder different from your current working directory, use the *--target* option:

```
php hacksearch.php --target=/home/hacksearch/public_html
```

### Pipeing the output to a different software

If you would like to pipe the output to a different software/command, you would most probably want to supress the output. You can do so by using '-s' and '-q' options:

```
php hacksearch.php -q -s
```

### Joomla and WordPress specific features

If you are using Joomla 3.0+ or WordPress 2.0+, you can enable application focus by passing 'appfocus=Joomla' or 'appfocus=WordPress'. The feature checks the md5sum of all default core files of the application and marks those that are modified.

### Change Log

Version 2.3.0 - Updated core code and include application search feature

Version 2.2.1 -- Added Joomla/Wordpress appfocus feature



