#!/usr/bin/env python3
filesize=0x6d8c9+1 # size of sbconly.pcap
pcapInitSpacing=0x2b+1 # to skip pcap headers
pcapDataSpacing=0x13+1 # to skip frame headers in pcap
frameHeader=0x15 
packetHeader=0x4
packetSize=0x4e+1
f=open('sbconly.pcap','rb')
o=open('flag.sbc','wb')

ptr=pcapInitSpacing
while ptr<filesize:
	ptr+=frameHeader
	f.seek(ptr)
	cnt=int.from_bytes(f.read(1),'big')
	ptr+=1
#	print(hex(cnt)+'at'+hex(ptr)+'\n')
	f.seek(ptr)	
	o.write(f.read((packetSize+packetHeader)*cnt))
	ptr+=(packetSize+packetHeader)*cnt+pcapDataSpacing
f.close()
o.close()