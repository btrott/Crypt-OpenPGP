#!/usr/bin/perl -n

chomp;
s!\s+!!g;
push @words, $_;
if (@words == 4) {
    printf "                %-15s%-15s%-15s%-.15s\n", @words;
    @words = ();
}
