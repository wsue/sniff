# sniff
sniff tool for embeD linux system, it can capture network traffic and save it as pcap file, and do simple decode.

*** SNIFF   ***
a lightly sniff tool run in linux, it don't depend any other running librarys.
and provide these function:
1.  sniff from ether device, or read package from pcap file.
2.  simple decode sniff result to screen.(can easy add new show content)
3.  write sniff result to pcap file(-w), so you can use other strong pcap parse tool(such as tcpdump, wireshark) to parse the package
4.  provide simple filter syntax. can filter by protocol(-P), or by ip address,port(- F 'filter string').
5.  use BPF to faster filter performance.
6.  use zero copy to faster recv performance.
7.  provide string filter(-m or -M), to filter show content.

##   compile:
    cmake .
    make

##  run:
    ./sniff -i eth0 
    ./sniff -i eth0 -P TCP
    ./sniff -i eth0 -F 'TCP{PORT=80}'
    ./sniff -i eth0 -F 'IP{10.90.1.12}'
    ./sniff -i eth0 -F 'IP{10.90.1.12}TCP{PORT=80}'
    ./sniff -h

*** 中文介绍    ***
这是一个轻量级的抓包工具, 在linux上运行,并且不需要依赖其它库.
它提供以下功能:
1.  从网卡抓包, 或是从pcap文件中读取待分析的内容.
2.  在屏幕上简单显示抓到的内容, 并且可以扩展显示新内容.
3.  支持把抓包结果写成pcap文件格式,以方便使用更高级工具(例如tcpdump, wireshark)分析.
4.  支持过滤语法组合,可以按协议过滤(-P), 或是按IP、端口、MAC过滤(-F).
5.  使用 BPF 过滤方式提高性能，并且可以方便的增加自己的 BPF 过滤语法.
6.  使用零拷贝技术提高性能
7.  支持显示内容过滤(-m -M选项).
##   编译:
    cmake .
    make

##  运行:
    ./sniff -i eth0 
    ./sniff -i eth0 -P TCP
    ./sniff -i eth0 -F 'TCP{PORT=80}'
    ./sniff -i eth0 -F 'IP{10.90.1.12}'
    ./sniff -i eth0 -F 'IP{10.90.1.12}TCP{PORT=80}'
    ./sniff -h
