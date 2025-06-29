<?php
require_once('config.inc.php');
include ("language/$language.php");


function list_jails()
{ global $f2b; $jails=array();
  $erg=@exec($f2b['client'].' status | grep "Jail list:" | awk -F ":" \'{print $2}\' | awk \'{$1=$1;print}\'');
  $erg=explode(",",$erg); foreach($erg as $i=>$j){ $jails[trim($j)]=false; }
  ksort($jails); return $jails;
}

function jail_info($jail)
{ global $f2b; $info=array();
  $erg=@exec($f2b['client'].' get '.escapeshellarg($jail).' findtime ');
  if(is_numeric($erg)){ $info['findtime']='findtime: '.$erg; }
  $erg=@exec($f2b['client'].' get '.escapeshellarg($jail).' bantime ');
  if(is_numeric($erg)){ $info['bantime']='bantime: '.$erg; }
  $erg=@exec($f2b['client'].' get '.escapeshellarg($jail).' maxretry ');
  if(is_numeric($erg)){ $info['maxretry']='maxretry: '.$erg; }
  return $info;
}

function list_banned($jail)
{ global $f2b; $banned=array();
  $erg=@exec($f2b['client'].' status '.$jail.' | grep "IP list:" | awk -F "list:" \'{print$2}\' | awk \'{$1=$1;print}\'');
  if($erg!='')
  { $banned=explode(" ",$erg);
    natsort($banned);
    if($f2b['usedns']===true)
    { foreach($banned as $i=>$cli)
      { $dns=gethostbyaddr($cli);
        if($dns==$cli){ $dns=' (unknown)'; } else { $dns=' ('.$dns.')'; }
        $banned[$i].=$dns;
      }
    } return $banned;
  }
  return false;
}

function ban_ip($jail,$ip)
{ global $f2b;
  if($jail==''){ return 'nojailselected';  }
  elseif(!validateCidr($ip)) { return 'novalidipaddress'; }
  $erg=@exec($f2b['client'].' set '.escapeshellarg($jail).' banip '.escapeshellarg($ip));
  if($erg!=1){ return 'couldnotbanthisip'; }
  return 'OK';
}

function unban_ip($jail,$ip)
{ global $f2b;
  if($jail==''){ return 'nojailselected'; }
  elseif(!validateCidr($ip)) { return 'novalidipaddress'; }
  $erg=@exec($f2b['client'].' set '.escapeshellarg($jail).' unbanip '.escapeshellarg($ip));
  if($erg!=1){ return 'couldnotunbanthisip'; }
  return 'OK';
}

function validateCidr($cidr)
{
  $parts=explode('/',$cidr);
  $ip=$parts[0];
  $netmask=0;
  if(count($parts)>1){ $netmask=intval($parts[1]); }
  if(count($parts)>2){ return false; }
  if($netmask<0){ return false; }
  if(filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)) { return($netmask<=32); }
  if(filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV6)) { return($netmask<=128); }
  return false;
}

function is_authenticated()
{
  if(!isset($_SESSION['username'])) {
    do_login_form();
    exit();
  }
}

function do_login_form()
{ global $f2b;
  $login_message="";
  if($_SERVER['REQUEST_METHOD'] === 'POST') {
    if(!preg_match('/^[A-Za-z0-9_\-\@\.]{3,64}$/', $_POST['username']) || !preg_match('/^[A-Za-z0-9_\-\@\~\.\`\!\"\#\$\%\^\&\*\(\)\+\=\/]{3,30}$/', $_POST['password'])) {$login_message="Bad Username or Password!";}
    else {
      $username=$_POST['username']; $password=$_POST['password'];
      $auth_function = $f2b['auth-func'];
      if($auth_function($username, $password)) {
        session_regenerate_id();
        $_SESSION['username']=$username;
        header("Location: ".$_SERVER['SCRIPT_NAME']);
      } else {
        $login_message="Bad Username or Password!";
        openlog('f2b-webinterface', LOG_PID, LOG_MAIL);
        syslog(LOG_WARNING, sprintf("login failed for %s from %s", $username, $_SERVER['REMOTE_ADDR']));
        closelog();
      }
    }
  }

  echo <<<EOT1
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<link rel="stylesheet" href="style.css" type="text/css" charset="utf-8">
<title>Fail2Ban Webinterface - Login</title>
</head>
<body>
<div id="container">
<form name="frmUser" method="post" action="">
<div font class="msg_er">
EOT1;
  if($login_message!="") {echo $login_message;}
  echo <<<EOT2
</div>
<table>
<caption><h1>Fail2Ban Webinterface - Login</h1></caption>
<tr><td><label>Username:</label></td><td><input type="text" name="username" id="username" class="login_form" required></td></tr>
<tr><td><label>Password:</label></td><td><input type="password" name="password" id="password" class="login_form" required></td></tr>
<tr><td colspan="2" align="center"><input type="submit" name="login" value="Login"></td></tr>
</table>
</form>
</div>
</body>
</html>
EOT2;
}

### Inspired by https://gist.github.com/wrossmann/7685647
# SQL-free doveadm-only username-password verificator, PFA only mailbox accounts
function pfa_doveadm_user($username, $password) {
  $descriptors = array(
    0 => array('pipe', 'r'),
    1 => array('pipe', 'w'),
    2 => array('pipe', 'w'),
  );
  $cwd = sys_get_temp_dir();
  $proc = proc_open(
    '/bin/doveadm auth test ' . escapeshellarg($username),
    $descriptors, $pipes, $cwd
  );
  if(!is_resource($proc)) {echo 'failed to create auth process'; exit;}
  fwrite($pipes[0], $password);
  fclose($pipes[0]);
  $stdout = stream_get_contents($pipes[1]);
  $stderr = stream_get_contents($pipes[2]);
  fclose($pipes[1]);
  fclose($pipes[2]);
  $rval = proc_close($proc);
  return ($rval == 0) ? true : false;
}

# SQL and doveadm-only username-password verificator, PFA mailbox or admin accounts
function pfa_doveadm_admin($username, $password) {
  global $f2b;
  $dbh = new mysqli($f2b['sql-host'], $f2b['sql-dbuser'], $f2b['sql-passwd'], $f2b['sql-dbname']);
  $sth = $dbh->prepare("SELECT `password` FROM admin WHERE `username`=?");
  $sth->bind_param("s", $username);
  $sth->execute();
  $sth->bind_result($password_hash);
  $sth->fetch();
  $dbh->close();
  $descriptors = array(
    0 => array('pipe', 'r'),
    1 => array('pipe', 'w'),
    2 => array('pipe', 'w'),
  );
  $cwd = sys_get_temp_dir();
  $proc = proc_open(
    '/bin/doveadm pw -r 12 -s CRAM-MD5 -t '.$password_hash,
    $descriptors, $pipes, $cwd
  );
  if(!is_resource($proc)) {echo 'failed to create auth process'; exit;}
  fwrite($pipes[0], $password);
  fclose($pipes[0]);
  $stdout = stream_get_contents($pipes[1]);
  $stderr = stream_get_contents($pipes[2]);
  fclose($pipes[1]);
  fclose($pipes[2]);
  $rval = proc_close($proc);
  return ($rval == 0) ? true : false;
}

# SQL only username-unencrypt password verificator, PFA mailbox or admin accounts
function pfa_sql_admin($username, $password) {
  global $f2b;
  $dbh = new mysqli($f2b['sql-host'], $f2b['sql-dbuser'], $f2b['sql-passwd'], $f2b['sql-dbname']);
  $sth = $dbh->prepare("SELECT `password` FROM admin WHERE `username`=?");
  $sth->bind_param("s", $username);
  $sth->execute();
  $sth->bind_result($password_hash);
  $sth->fetch();
  $dbh->close();
  return ($password_hash == $password) ? true : false;
}

?>
<!-- vim: set syntax=php ts=2 sw=2 sts=2 sr et: -->
