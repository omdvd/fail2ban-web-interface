<?php


#####################
# FAIL2BAN SETTINGS #
#####################

$f2b['usedns']=true; # show hostnames per banned IP [true|false]
$f2b['noempt']=true; # do not show jails without banned clients [true|false]
$f2b['jainfo']=true; # show jail information in table headers [true|false]
$f2b['client']='sudo /usr/bin/fail2ban-client'; # path to fail2ban-client with sudo prefix
$language='ptbr'; #change language available options are English [en] or Brazilian Portuguese [ptbr]

######################
# DO NOT EDIT PLEASE #
######################
$f2b['version']='0.2a (2024-01)';

?>
