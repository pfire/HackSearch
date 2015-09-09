# HackSearch

## v2.2.1 

HackSearch is a malware search tool written in PHP. Its mainly focused on detecting compromised/hacked files in PHP web based applications, such as Joomla, WordPress, Magento, etc.

### Requirements
* PHP v 5.3.10+
* Ability to run as CLI (i.e. SSH/Crontab/etc)
* Linux / Unix based server

### Common Usage

The most common way to run the program is by downloading it and passing it to the PHP CLI. The following command will do just that in your current directory:
`curl -sS https://raw.githubusercontent.com/pfire/HackSearch/master/hacksearch.php | php-cli`
