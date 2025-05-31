<?php


#####################
# FAIL2BAN SETTINGS #
#####################

$f2b['usedns']=true; # show hostnames per banned IP [true|false]
$f2b['noempt']=true; # do not show jails without banned clients [true|false]
$f2b['jainfo']=true; # show jail information in table headers [true|false]
$f2b['client']='sudo /usr/bin/fail2ban-client'; # path to fail2ban-client with sudo prefix
$f2b['sql-host']='localhost';
$f2b['sql-dbname']='postfix';
$f2b['sql-dbuser']='postfix';
$f2b['sql-passwd']='***';
$f2b['auth-func']='pfa_doveadm_admin'; # Auth function [pfa_doveadm_admin|pfa_doveadm_user|pfa_sql_admin]
$language='ptbr'; #change language available options are English [en] or Brazilian Portuguese [ptbr]

######################
# DO NOT EDIT PLEASE #
######################
$f2b['version']='0.2a (2024-01)';

# Override settings in local configuration file
require_once('config-local.inc.php');
?>
