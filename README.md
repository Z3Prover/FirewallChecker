# FirewallChecker

A firewall analysis library using the Z3 SMT Solver from Microsoft Research.
Includes console applications to check the equivalence of two firewalls, or analyze the action of a firewall on a single packet.
It was developed for use inside Microsoft Azure to analyze changes to Windows Firewall generation logic.

The underlying principles of operation are explained in the blog post [Checking Firewall Equivalence with Z3](https://medium.com/@ahelwer/checking-firewall-equivalence-with-z3-c2efe5051c8f), and are based on the whitepaper [Checking Cloud Contracts in Microsoft Azure](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/nbjorner-icdcit2015.pdf) by Nikolaj Bjørner and Karthick Jayaraman.

## Build & Test

1. Install [Visual Studio 2017](https://visualstudio.microsoft.com/downloads/)
2. Install [.NET Framework 4.7.2](https://www.microsoft.com/net/download)
3. Install [NuGet Commandline](https://www.nuget.org/downloads)
4. Clone the repo
5. Open x64 Native Tools Command Prompt for VS 2017 and `cd` to the repo root
6. Run `nuget restore` to download required packages
7. To build in debug mode, run `msbuild`
8. To test, run `vstest.console .\FirewallAnalysis.Tests\bin\debug\Microsoft.FirewallAnalysis.Tests.dll`
9. To build in release mode, run `msbuild /p:Configuration=Release`

Alternatively, you can build & test from Visual Studio 2017 by opening the solution.
In order to run tests from Visual Studio, you must ensure both the Solution Platform and Default Test Processor Architecture are set to x64.

## Usage

This project includes two simple console applications, one which checks the equivalence of two firewalls and another which analyzes the action of a firewall on a single packet.
In addition to their standalone utility, they also server as simple examples for writing more advanced applications against the Firewall Analysis library.

### Firewall Input Format

The FirewallChecker consumes files of tab-separated firewall rules like those exported from Windows Firewall. To export the firewall rules of a given computer, do the following:

  1. Open the Windows Run prompt with `win+r`
  2. Run `mmc` (the Microsoft Management Console)
  3. Open the "Add or Remove Snap-ins" prompt with `ctrl+m`
  4. Add the "Windows Defender Firewall with Advanced Security" snap-in
  5. Click "Inbound Rules" or "Outbound Rules"
  6. Right-click the same inbound or outbound rules and click "Export List..."
  7. Save the tab-separated output file

The resulting file can be fed into the FirewallChecker, either for standalone analysis or comparison with a different firewall file.

### Firewall Equivalence Checker

The Firewall Equivalence Checker compares two firewall rule files for logical equivalence, meaning they block or allow the same set of packets.
If the two firewalls are not equivalent, the tool outputs a list of packets (default 10) treated differently by each firewall.
The tool also lists firewall rules acting on the packets, easing debugging. Only IPv4 rules are currently supported.

Two minimal tab-separated example firewall rule files are as follows (see [Examples](./Examples) directory):

Firewall 1:
```
Name	Enabled	Action	Local Port	Remote Address	Remote Port	Protocol
Foo1	Yes	Allow	100	10.3.141.0	100	UDP
Bar1	Yes	Allow	200	10.3.141.0	200	TCP
```

Firewall 2:
```
Name	Enabled	Action	Local Port	Remote Address	Remote Port	Protocol
Foo2	Yes	Allow	100	10.3.141.0	100	UDP
Bar2	Yes	Allow	200	10.3.141.1	200	TCP
```

This generates the following output from `FirewallEquivalenceCheckerCmd.exe`:

```
Microsoft.FirewallEquivalenceCheckerCmd.exe --firewall1 .\firewall1.txt --firewall2 .\firewall2.txt
Parsing first firewall...
Parsing second firewall...
Running equivalence check...
Firewalls are NOT equivalent.

Inconsistently-handled packets:
-------------------------------------------------------------------------
|  PID |     Src Address | Src Port | Dest Port | Protocol | Allowed By |
-------------------------------------------------------------------------
|    0 |      10.3.141.0 |      200 |       200 |      TCP |      First |
|    1 |      10.3.141.1 |      200 |       200 |      TCP |     Second |
-------------------------------------------------------------------------

Firewall rules matching inconsistently-handled packets:
-------------------------------------------------------------------------
|  PID | Firewall | Action | Rule Name                                  |
-------------------------------------------------------------------------
|    0 |    First |  Allow | Bar1                                       |
|    1 |   Second |  Allow | Bar2                                       |
-------------------------------------------------------------------------
```

In the above, we have two packets with packet ID (PID) 0 and 1 which are treated differently by each firewall.
The PID serves as a foreign key for the second table, which lists the rules (possibly multiple) applying to each inconsistently-handled packet.


When parsing Windows Firewall rule files, there are various elements such as port macros (ex. "RPC Dynamic Ports") which the parser does not handle.
These rules are simply ignored, with a warning message printed to the console for each line.

Run `Microsoft.FirewallEquivalenceCheckerCmd.exe --help` to see the documented list of command-line parameters.

### Firewall Query

The Firewall Query tool analyzes a single firewall.
The tool takes as input a firewall rule file and the description of a single packet.
The tool then outputs whether the firewall blocks or allows that packet, as well as a list of all firewall rules acting on that packet.
Using Firewall 1 from above, we can execute a simple example query:

```
Microsoft.FirewallQueryCmd.exe --firewall .\firewall1.txt --srcAddress 10.3.141.0 --srcPort 100 --dstPort 100 --protocol UDP
Parsing firewall rules...
Checking action of firewall on packet...
Packet is allowed by firewall.

Firewall rules matching the test packet:
-------------------------------------------------------------------------
| Action | Rule Name                                                    |
-------------------------------------------------------------------------
|  Allow | Foo1                                                         |
-------------------------------------------------------------------------
```

Note that there is no `---dstAddress` parameter, as the application only works for local Windows Firewall rulesets and so the destination address is assumed to be the computer on which the firewall rules live.

Run `Microsoft.FirewallQueryCmd.exe --help` to see the documented list of command-line parameters.
