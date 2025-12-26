

Retro browsing setup (DOS / DOSBox-X)
=====================================

This folder contains helper files (`LYNX.BAT`, `EMPTY.HTM`) and notes for
using a modern HTTP proxy together with DOSLYNX inside DOSBox‑X.


# 1. Download the required software

- **DOSBox‑X**  
  `https://dosbox-x.com/`

- **NE2000 packet driver**  
  `http://www.georgpotthast.de/sioux/packet.htm`

- **mTCP**  
  `https://www.brutman.com/mTCP/`  
  Direct download: `https://www.brutman.com/mTCP/download/mTCP_2025-01-10.zip`

- **DOSLYNX**  
  `https://archive.org/details/msdos_doslynx_browser`


# 2. Set up directories inside DOSBox‑X

- **mTCP**  
   Unpack `mTCP_2025-01-10.zip` into a directory that will be mounted
   in DOSBox‑X as `C:\MTCP`.

- **DOSLYNX**  
   Unpack `doslynx.zip` into a directory that will be mounted
   in DOSBox‑X as `C:\LYNX`.

- **Helper files**  
   Copy `LYNX.BAT` and `EMPTY.HTM` into the same directory
   (mounted as `C:\LYNX`).

- **Point DOSLYNX to your proxy**  
   Edit `LYNX.BAT` and change the `PROXYBASE` variable so that it points
   to the IP address (and port, if needed) of your local proxy server.

- **Networking in DOSBox‑X**  
   Follow the DOSBox‑X networking guide and use the **PCAP** backend:  
   `https://dosbox-x.com/wiki/Guide:Setting-up-networking-in-DOSBox-X`


# 3. Browsing the web

- Start DOSBox‑X with networking enabled.  

- At the DOS prompt, run a command like:

   `LYNX.BAT http://example.com`

   (replace `http://example.com` with any valid URL)

- Optionally, add `C:\LYNX` to your `PATH` in the `[autoexec]` section
   of the DOSBox‑X configuration file so you can run `LYNX.BAT`
   from anywhere:

   `SET PATH=C:\LYNX;%PATH%`


# 4. Current limitations

At the moment, I was not able to make `DOSLYNX.EXE` fetch web pages directly from the network.

Instead, `LYNX.BAT` works as a small wrapper that:

1. Fetches the web page using `HTGET` from the mTCP package.  
2. Saves the result to `PAGE.HTM`.  
3. Opens the locally saved `PAGE.HTM` with DOSLYNX.

Because of this, **you cannot follow links directly from within DOSLYNX**.  
To open another page, exit DOSLYNX and run `LYNX.BAT` again with
the new URL.

------

DOSLYNX may fail to load large webpages.