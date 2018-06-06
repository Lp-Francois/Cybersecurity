# Cybersecurity

## Risk Generalities

```
"Every security rule or recommendation must be accompanied by its justification
in order to net be rejected or by-passed"

Trusted networks zone = networks on which we master the security
```

### Sniffing
Consists to catch  a traffic image of the network.

>For the hacker, the goal is to get information to prepare the attack

/!\ If someone if sniffing, he can see in `plaintext` all the messages using telnet, http, etc...

### TCP spoofing

TCP uses a Three-way handshake.
![Three-way handshake](https://github.com/AsterYujano/Cybersecurity/blob/master/img/3wayhs.PNG)
1. The first packet is a SYNC. The sequence number is A.
2. Answering  a SYNC-ACK packet. The sequence number is B and the acknowledgment number is (A+1).
3. Sequence number A+1 and acknowledgment number B+1

The hacker replaces his IP address by an other source address that he wants to spoof. The victim will send its answer to the spoofed source address indicated in the SYN packet sent by the hacker.
This answer SYN+ACK contains the sequence number chosen by the victim that the hacker needs to continue his attack and send data to the victim.

Then there are 2 cases : 

* TCP spoofing on the same sub-network.
By sniffing, hacker may observe victim answers even if these answers are not for his destination. The hacker will see the sequence number that the victim will propose in its answer so he will be able to construct a correct ACK packet to establish the connexion

* TCP spoofing on being externally to the victim or usurped machine sub-network. The hacker as to guess the next sequence number. This one is coded on 32 bits. 2^32 possibilities...

### SYN flooding Attack

SYN Flood attack corresponds to a client who doesn’t answer to the SYN-ACK.


***
***
***
***
___


* Define the sniffing concept when talking about network security

* Explain why it may be difficult to perform TCP spoofing						

* Explain the concept of "SYN flooding" attack							

In terms of network security, what is a DOS ? And a DDOS ?							

Explain the concept of Botnets and what can be done to fight them							

Give recommendations to fight against various types of keyloggers							

The chief information officer asks you to expose him the various organizational and technical means that will help the company to struggle against virus and worms 					

In Information System Security, give the two characteristics associated to the concept of risk							

Explain how DICP four characteristics are used to define information System resource security needs	

In security terms, according to you what is the greatest risk when using cookies to maintain sessions							
						




