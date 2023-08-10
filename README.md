# KDT_Scanner_proj
only for KDT Group 2 named 'Yu-iL-Mu-Yee'

## How to run
Options are adjusted using argparse.    
Default Usage:
<pre><code>
python main.py [host_name][start_port-end_port]
</code></pre>
options:
<pre><code>
-sS: Use SYN scan mode
-sT: Use Connect scan mode (also it is default scan mode in this program)
--rand-src: Use random source port
</code></pre>