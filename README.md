# KDT_Scanner_proj
only for KDT Group 2 named 'Yu-iL-Mu-Yee'

## How to run
Options are adjusted using argparse.    
Default Usage:
<pre><code>
python main.py [host_name]
</code></pre>
options:
<pre><code>
-sS: Use SYN scan mode
-sT: Use Connect scan mode (also it is default scan mode in this program)
-sn: Use ICMP ping scan mode
-sV: Use Service detection
-O: Use OS detection
--rand-src: Use random source port
-p: Port range to scan (e.g., 1-100 or 22,44,80)
</code></pre>