rule unknown_threat_ssh_one
{
  strings:
    $a = "darkl0rd.com" ascii nocase
    $b = "http://darkl0rd.com:7758/SSH-T" ascii
    $c = "http://darkl0rd.com:7758/SSH-One" ascii
    $d = "chmod +x /tmp/SSH-One" ascii
    $e = "/etc/rc.local" ascii

  condition:
    ($a and $b) or ($a and $c) or ($b and $c)
    and $d and $e
}
