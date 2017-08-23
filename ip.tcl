############################################################################
# BlackIP 1.5
#!ip <ip> / <host> / <nickname>
# - Now supports IPv6
#
#To activate .chanset #channel +ip | BlackTools : .set +ip
#
#To work, put the two tcl's in config from the arhive : json.tcl , http.tcl
#                                   (if you don't have them instaled)
#
#                                             BLaCkShaDoW ProductionS
#                       WwW.TclScripts.Net
###########################################################################
 
#Set here who can execute the command (-|- for all)
 
set ip_flags "-|-"
 
############################################################################
 
bind pub $ip_flags !ip black:ip:check
 
package require http
package require json
 
setudef flag ip
 
proc black:ip:check {nick host hand chan arg} {
   
    set ip [lindex [split $arg] 0]
    set ::chan $chan
    set ::ip $ip
 
if {![channel get $chan ip]} {
return
}
if {$ip == ""} {
    puthelp "NOTICE $nick :\[BlackIP\] USAGE: \002!ip\002 <ip>/\002<host>\002/<nick>"
return
}
    set check_ipv6 [regexp {^([0-9A-Fa-f]{0,4}:){2,7}([0-9A-Fa-f]{1,4}$|((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4})$} $ip]
    set check_ipv4 [regexp {^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$} $ip]
   
if {![string match -nocase "*:*" $ip] && ![string match -nocase "*.*" $ip]} {
    putquick "WHOIS $ip $ip"
    bind raw - 401 no:nick
    bind raw - 311 check:for:nick
    return
}
 
if {$check_ipv6 == "0" && $check_ipv4 == "0"} {
    dnslookup $ip solve:ip $chan
return
}
    check:ip $ip $chan 0 none
}
 
proc no:nick { from keyword arguments } {
    set chan $::chan
    set ip $::ip
    puthelp "PRIVMSG $chan :\[\00304$ip\003]\ is not Online."
    unbind raw - 401 no:nick
}
 
proc solve:ip {ip host receive chan} {
if {$receive == "1"} {
    check:ip $ip $chan 2 $host
    } else {
    puthelp "PRIVMSG $chan :\[\00304X\003\] unable to resolve address \00314$host\003."
    }
}
 
proc solve:nick:ip {ip host receive chan nick} {
if {$receive == "1"} {
    check:ip $ip $chan 3 "$host $nick"
    } else {
    puthelp "PRIVMSG $chan :\[\00304X\003\] unable to resolve address \00314$host\003 from \00303$nick\003."
    }
}
 
proc check:for:nick { from keyword arguments } {
 
    set chan $::chan
    set getip [lindex [split $arguments] 3]
    set getnick [lindex [split $arguments] 1]
 
    set check_ipv6 [regexp {^([0-9A-Fa-f]{0,4}:){2,7}([0-9A-Fa-f]{1,4}$|((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4})$} $getip]
    set check_ipv4 [regexp {^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$} $getip]
if {$check_ipv6 == "0" && $check_ipv4 == "0"} {
    dnslookup $getip solve:nick:ip $chan $getnick
    unbind raw - 311 check:for:nick
    unbind raw - 401 no:nick
return
}
    check:ip $getip $chan 1 $getnick
    unbind raw - 311 check:for:nick
    unbind raw - 401 no:nick
}
 
 
proc check:ip {ip chan status arg} {
global botnick
    set ipq [http::config -useragent "lynx"]
    set ipq [::http::geturl "http://ipinfo.io/$ip/json"]
    set data [http::data $ipq]
    set parse [::json::json2dict $data]  
    set location ""
    set hostname ""
    set org ""
foreach {name info} $parse {
if {[string equal -nocase $name "hostname"]} {
if {$info != "No Hostname"} {
    set hostname $info
    }
}
if {[string equal -nocase $name "city"]} {
if {$info != ""} {
    lappend location $info
    }
}
 
if {[string equal -nocase $name "region"]} {
if {$info != ""} {
    lappend location $info
    }
}
 
if {[string equal -nocase $name "country"]} {
if {$info != ""} {
    lappend location $info
    }
}
if {[string equal -nocase $name "org"]} {
if {$info != ""} {
    set org $info
        }
    }
}
 
if {$org != ""} {
    set org_text "|\00302 ORG: \00310$org\003"
} else { set org_text "" }
    set location [join $location ", "]
 
if {$status != 0} {
   
if {$status == "1"} {
if {$hostname != ""} {
        putserv "PRIVMSG $chan :\00302NickName: \00303$arg\003 | \00302Ip: \00304$ip\003 | \00302Host: \00304$hostname\003 |\00302 Location: \00314$location\003 $org_text"
} else {
    putserv "PRIVMSG $chan :\00302NickName: \00303$arg\003 | \00302Ip: \00304$ip\003 |\00302 Location: \00314$location\003 $org_text"
    }
}
if {$status == "2"} {
    putserv "PRIVMSG $chan :\00302Host: \00306$arg\003 | \00302Ip: \00304$ip\003 |\00302 Location: \00314$location\003 $org_text"
}
 
if {$status == "3"} {
    putserv "PRIVMSG $chan :\00302NickName: \00303[lindex $arg 1]\003 | \00302Host: \00306[lindex $arg 0]\003"
if {$hostname != ""} {
    putserv "PRIVMSG $chan :\00302Ip: \00304$ip\003 | \00302Host: \00304$hostname\003 |\00302 Location: \00314$location\003 $org_text"
} else {
    putserv "PRIVMSG $chan :\00302Ip: \00304$ip\003 |\00302 Location: \00314$location\003 $org_text"
    }
}
} else {
if {$hostname != ""} {
    putserv "PRIVMSG $chan :\00302Ip: \00304$ip\003 | \00302Host: \00304$hostname\003 |\00302 Location: \00314$location\003 $org_text"
} else {
    putserv "PRIVMSG $chan :\00302Ip: \00304$ip\003 |\00302 Location: \00314$location\003 $org_text"
        }
    }
}
 
putlog "BlackIP 1.5 (IPv6 support) by BLaCkShaDoW Loaded"