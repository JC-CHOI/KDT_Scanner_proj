# KDT_Scanner_proj
Only for KDT Group 2 named 'Yu-iL-Mu-Yee'   

This program is a simple network scanner using Python.


## How to run
Options are adjusted using argparse.    

Required Installation:
<pre><code>
pip install scapy
</code></pre>

Default Usage:
<pre><code>
python main.py [host_name]
</code></pre>
   
Scan Options:
<pre><code>
-sS: Use SYN scan mode
-sT: Use Connect scan mode (also it is default scan mode in this program)
-sV: Use Service detection
-O: Use OS detection

-sn [targets]: Use ICMP ping scan mode (this mode does not operate in conjunction with other TCP scans)
</code></pre>
Input type for ping scan target: 127.0.0.1-10, url, CIDR   

Port Options:
<pre><code>
--rand-src: Use random source port
-p [ports]: Port range to scan (e.g., 1-100 or 22,44,80)
--top-port [num]: Scan top ports up to the specified number
</code></pre>
