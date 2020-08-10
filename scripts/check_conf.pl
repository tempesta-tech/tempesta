#!/usr/bin/env perl

`modprobe msr`;

sub test {
    print "'$_[0]' bit: ",
    (hex(`rdmsr $_[1]`) & (1 << $_[2]) ? "" : "NOT "), "found\n";
}

test 'Activate secondary controls', 0x482, 63;
test 'Virtualize APIC accesses', 0x48b, 32;
test 'APIC-register virtualization', 0x48b, 40;
test 'Virtual-interrupt delivery', 0x48b, 41;

print "'Process posted interrupts' bit: ",
    (((hex(`rdmsr 0x480`) & (1 << 55))
      && (hex(`rdmsr 0x48d`) & (1 << 39)))
     || (hex(`rdmsr 0x481`) & (1 << 39)))
    ? "" : "NOT ", "found\n";
