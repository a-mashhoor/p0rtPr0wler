# P0rt Pr0wler
**Port Prowler** is a standalone port scanner I created from scratch using
only Python's built-in modules.
![Port Prolwer logo.](https://github.com/a-mashhoor/p0rtPr0wler/blob/main/assets/p0rtPr0wler.png)


## Description:

As You can read in About section, `Port Prowler` is a standalone port scanner
I created from scratch using only Python's built-in modules,
if we're not counting “pyfiglet” library
which I used it to generate simple ASCII arts.

The tool is built with and for Kali Linux and other UNIX-Based or UNIX-Like operating systems,
although it currently only tested on a Kali Linux, Linux mint, and Arch Linux machines.

**But Why I created it?**

When a complete tool like “Nmap” exists, there is no need for another port scanner,
specially when it is slower than the alluded tool and certainly contains fewer features,
features like OS detection and trace routing functionalities!

The whole purpose of building port prowler was educational for me: my final project for cs50x.

I wanted to create something that had never been created using only Python:
building a complete UDP and TCP port scanner that actually works, it is concurrent,
and it uses the multithreading module and multiprocessing module simultaneously, so I did!

**How it works?**

For this project, I decided not to use the Scapy library,
so I created multiple classes, a class that creates packets,
ironically and thoughtfully, I named it Create Packet Class :).

I wrote the entire process of creating packets from scratch, part by part.
The Class supports TCP packets, UDP packets, and ICMP packets.
For this class, each of the headers had to be written separately
and checksum calculation was a necessity for each of the individual headers manually.
The amount of work that had to be done for this single class was substantial,
not to mentioning other classes.

Another class that I had to create was the Sniffer class,
that, as the name indicates, sniffs the network, but it does so much more.
It captures all the transmitted packets on all the interfaces.
Then it filters the packets based on the target IP and source IP, it also analyzes any received
packet and categorizes packets based on the protocol. For ICMP packets that the class captured with
type 3 and code 3, It will check the content of the packet for a UDP response from our target!

Scanning TCP ports was really straightforward and easy,
but unfortunately that was not the case with UDP scanning.
The UDP protocol is really tricky to work with, and I had to use custom payloads that are
specifically written in bytes data type for each of the ports individually.
I built a few payloads to start, and I plan to write as many as I possibly can in the future,
but for now that's it.

I decided the “OPEN|FILTERED” ports are not really important for us to include in the results
of the scan, so the scanner will only show any result if the tool
is certain about the state of the target ports.

Also, the tool supports multiple types of scans classified in two major types: Simple and Advanced
for simple scans : `simple tcp scan, simple udp scan, simple udp and tcp scans`
and for advanced scans we have `advanced tcp scan, advanced udp scan, advanced udp tcp scans`
although all of them will use the same analyzer that by design uses RAW sockets,
this methodology was the only one that worked.
And as a consequence of using raw sockets, root privileges are necessary
for the tool to work properly, (so make sure you are root user when using it).

For output, the user can both store the results as a text based ASCII file
or as JSON data type, personally I prefer working with JSON data type.


## installation:
**using the binary release!**

You simply use the binary [Release](https://github.com/a-mashhoor/p0rtPr0wler/releases/download/v1.0.0/p0rtPr0wler)
and give the executable permission to execute!

```shell
chmod a+x ./p0rtPr0wler
```

And you can simply run it ./p0rtPr0wler
or you can add it to your PATH somewhere like
/usr/bin or ~/.local/bin/
also, you can use symbolic links

another way is to run the script using python
The tool is built using python3.12
for using it, you need to have python3.12 or higher versions
You can simply enough install the requirements using pip inside a virtual environment
```bash
$ python3 -m venv .env && source .env/bin/activate && pip install -r requiremnets.txt
```

## Usage:
With a simple `-h or --help` you can discover all the tool features
![Help](https://github.com/a-mashhoor/p0rtPr0wler/blob/main/assets/usage.png)

### Example:
for example, you can scan any IP or FQDN
you can specify single port:`-p 443`, range of ports: `-pr 1 1000` , all ports: `-ap`,
or multiple ports: `-pl 53 443 853`

you can determine the output to be JSON using `-oj name_of_file`

```shell
./p0rtPr0wler -H fqdn or ip -p 443 -tSA -oj output_file.json

```
and more features to be discovered by you :)
happy hunting


## Disclaimer:
Port Prowler is an ethical hacking tool, that intended for educational
purposes and awareness training sessions only, Or on in-scope domains o
f bug bounty programs. Performing hacking attempts on computers that you do not own
(without permission) is **illegal**!
Do not attempt to gain access to a device that you do not own.

