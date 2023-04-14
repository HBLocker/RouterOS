### MicroTick at a glance 
!subject to change. Draft 1.5 libradious

Microtick at a Glance. 

I was looking at Shodan and was more looking at open devices and stumbled across Microtick routers. Which began this rabbit hole I gradually fell down….
```bash
product:"MikroTik"
```
![Router os open devices world wide ](https://www.shodan.io/search/facet.png?query=mikrotik&facet=country)


## RouterOS 

In RouterOS, the Linux kernel provides a stable and reliable foundation for managing network infrastructure. It is highly optimized for networking and supports a wide range of hardware, including network adapters, wireless cards, and routers. Additionally, RouterOS includes a range of networking services and features built on top of the Linux kernel, such as routing, firewall, NAT, wireless access point, hotspot, VPN, and more. 


### Understadning the NPK file format. 

The NPk format was developed by MicroTick as a way to bundel thier packages togther. This will contain all the software and applications for RouterOS. 

The compression used in NPK files is typically based on the LZMA algorithm, which is a popular data compression algorithm that provides a high compression ratio with relatively fast decompression times. LZMA works by finding repeated patterns in the data and replacing them with a smaller representation, resulting in a compressed file that is smaller in size than the original.

- Header - The header of the NPK file consists of the ASCII string "NPK" followed by four null bytes.

- Metadata - The metadata section contains information about the NPK package, such as the version number, architecture, and date of creation.

- File entries - The file entries section contains a list of files that are included in the NPK package, along with metadata for each file, such as the file name, size, and permissions.

- File data - The file data section contains the actual binary data for each file included in the NPK package.

- Signature - The signature section is optional and contains a digital signature for the NPK package, which can be used to verify the integrity and authenticity of the package.



### The CIA 
I mean do we think anything we own really isnt in some custom state sponored exploit kit? 

With no suprise when I found this, that within the vault 7 leaks where a cool rootkit developed by the CIA for Microtick routers.

ChimayRed is a buffer overflow exploit that targets a vulnerability in the Winbox component of MikroTik RouterOS. Winbox is a graphical user interface used to manage MikroTik devices and is included in the RouterOS distribution. The vulnerability allows an attacker to send a specially crafted packet to the Winbox service, causing a buffer overflow and executing arbitrary code on the target device.

The ChimayRed exploit was designed to work on MikroTik RouterOS versions 6.38.4 and earlier, which were released between 2016 and 2017. MikroTik has since released patches to address the vulnerability, and users are advised to update their RouterOS installations to the latest version to prevent exploitation.

It has since been patched. 


### UDP packet strcuture. 

Currently this is a WIP as I am reversing as much as one can do. 

With the shodan results, you can see the UDP packets have the following strcuture:

```
\xc8\x02\x00i\x00\x00\x00\x00\x00\x00\x00\x01\x80\x08\x00\x00\x00\x00\x00\x02\x80\x08\x00\x00\x00\x02\x01\x00\x80\n\x00\x00\x00\x03\x00\x00\x00\x01\x80\n\x00\x00\x00\x04\x00\x00\x00\x00\x00\x08\x00\x00\x00\x06\x00\x01\x80\x13\x00\x00\x00\x07rt1.pol2.gkb1\x00\x0e\x00\x00\x00\x08MikroTik\x80\x08\x00\x00\x00\t\x01}\x80\x08\x00\x00\x00\n\x00\x04
```
First, the packet starts with the source port number in hexadecimal format (\xc8\x02). In this case, it represents the value 51202 in decimal, which is the port from which the packet originated. The next two bytes (\x00\x69) represent the destination port number, which is zero in this case, indicating that the packet is not destined for a s
pecific port.

The remaining bytes of the packet represent the packet payload. The format of this payload is specific to RouterOS and appears to include a variety of settings and configuration parameters.

The payload starts with several null bytes (\x00\x00\x00\x00\x00\x00\x00\x01) followed by a series of values that are likely related to the device or service using RouterOS. These values include a mix of numeric values in hexadecimal format, ASCII strings (e.g., "rt1.pol2.gkb1"), and other data types.

Some of these values have specific meanings within the RouterOS system, such as the "MikroTik" string, which likely identifies the type of device or service using RouterOS. Other values are likely specific to the particular network configuration or service being used.


### Looking at some of the internels 

Some of the kernel os OpenSource other parts of the software are closed source, RouterOS is somewhat a blend of the two. 

We will be focusing here:
#### /nova/bin - system binaries

```bash
agent        console    fileman      kidcontrol   macping    mtget          profiler  sertcp   stopper     undo
arpd         convertbr  ftpd         lcdstat      mactel     net            ptp       smb      sys2        upnp
backup       crossfig   graphing     led          mepty      ntp            quickset  sniffer  telnet      user
bridge2      detnet     havecardbus  letsencrypt  mesh       panicsl        radius    snmp     telser      vrrp
btest        discover   igmpproxy    loader       mode       partd          resolver  socks    tftpd       watchdog
cerm         diskd      installer    log          modprobed  ping           romon     ssld     traceroute  wproxy
cerm-worker  dot1x      ippool       login        moduler    poeupdatefwv3  route     sstore   trafficgen  www
cloud        email      keyman       logmaker     mproxy     portman        sermgr    starter  trafflow
```

#### /nova/lib - system libraries

```bash 
console  defconf  profiler  xmlnames2
```

#### /nova/etc - system configuration
```
leds    lognames  log-prefix  net-remote  ports   services  system_names  url   www
loader  logo      manual-url  pciinfo     radius  starter   upnp          user
```
## /nova/bin/login


This binary is used to login to the device and has some interesting options such as the developer option. 
### Developer login

The strings "admin" and "devel" are used as part of a login check for a developer login option. The code compares the input password string with the string "devel" to check if the user is trying to log in as a developer. If the input password matches "devel", then the code proceeds to check if the user has the "admin" option package.

The use of these strings suggests that the binary has different login options for different types of users, such as a regular user and a developer. The "devel" string is used as an identifier for the developer login option, while the "admin" string is used as a flag to check if the user has the necessary option package to access certain functionalities. There has to be a 

```c
FUN_00014260 
LAB_00015970:
      if ((__nptr == (uint *)0x0) && (((uint)local_16c & (uint)local_168) == 0)) {
        __nptr = (uint *)getpass("Password: ");
        FUN_00013a94((byte *)__nptr);
      }
      nv::message::message((message *)&puStack_154);
      nv::message::insert_vector((u32_array_id)&puStack_154,0xff0001,0xd);
      iVar7 = strcmp((char *)puVar18,"devel");
      if ((iVar7 == 0) && (iVar7 = nv::hasOptionPackage(), iVar7 != 0)) {
        string::string((string *)local_108,"admin");
        nv::message::insert<nv::string_id>((string_id)&puStack_154,1);
        string::freeptr();
 ```
 
hasOptionPackage() function is being used to check whether the "option" package is installed or enabled, specifically for the "devel" login option. The login binary in question (/nova/bin/login) is responsible for authentication and contains this code for the purpose of enabling or disabling the "devel" login option based on whether the "option" package is available.
 
 
## Software updates 

 ### poeupdatefwv3 
   
   So, I had no idea what this was, I saw the binary and first opened it in Ghidra to try see what it is, I then googled the name and it is a MMO game (Path of Exile).    Sadly my excitment was depeleted when it is just a firmware update over the ethernet. But still! I reversed it and here is how this works!
   
 POE (Power over Ethernet) firmware is a type of firmware that enables devices to receive power and data over Ethernet cables. POE technology allows devices such as IP  cameras, wireless access points, and VoIP phones to be powered through the same Ethernet cable that transfers data.

POE firmware typically includes a set of protocols and standards that enable devices to negotiate the power requirements with the power sourcing equipment (PSE), such as a POE-enabled switch or injector. This negotiation ensures that the device only receives the power it needs, preventing damage due to overvoltage or overcurrent.

POE firmware is becoming increasingly common in networked devices, as it provides a convenient and cost-effective way to power devices in locations where access to electrical outlets may be difficult or impractical.
   


```c
void FUN_00010bf8(char *param_1)

{
  printf("usage: %s <poe_dev> [--ignore-pci] [--swd [--force-chiperase | --user-row 0xffffff5dd8e0c7 ff --lock-security]] [--force-spi]<file>\nExample:\n    %s /dev/poe1 --swd --force-chiperase spi_b ootloader.samd20\n"
         ,param_1,param_1);
  return;
}
```



 #### Main update function -  FUN_000115ac  
  
  
  First the function checks the size of the file and verifies it can be opened:
 #### File checking
```c
    uVar12 = (uint)param_9;
  pcVar3 = param_1;
  if (param_1 != (char *)0x0) {
    iVar1 = open(param_1,0);
    if (iVar1 < 0) {
      local_9000 = (char *)0xffffffe1;
      perror("open file");
LAB_00011624:
      return -(int)local_9000;
    }
 ``` 
 #### Memory erased 
 Next the memeory is erased, which uses the following Ioctl values 0x40046fd8, 0x40046fd9
 ```c
        poVar5 = (ostream *)operator<<((ostream *)cout,"Memory erasing... ");
        endl(poVar5);
        local_9030 = (undefined  [4])((uint)local_9030 & 0xffffff00);
        while( true ) {
          iVar18 = 100;
          do {
            uVar13 = FUN_00011020(iVar1,0x41002100,local_9030);
            if ((uVar13 & 0x100) != 0) {
              if (iVar2 == 0) goto LAB_0001192c;
              poVar5 = (ostream *)operator<<((ostream *)cout," done!");
              endl(poVar5);
              puts("SWD chip erase OK");
              local_9030 = (undefined  [4])0x0;
              ioctl(iVar1,0x40046fd8,local_9030);
              ioctl(iVar1,0x40046fd9,local_9030);
              uVar13 = FUN_000111c4(iVar1);
              goto LAB_000118cc;
            }
 ``` 
 #### Writing to memory 
 
 When calling --force-spi  this forces the update and to write over previous memeoy. 
 
  ```c
 LAB_00011c10:
          poVar5 = (ostream *)endl((ostream *)cout);
          poVar5 = (ostream *)operator<<(poVar5,"done!");
          endl(poVar5);
          if ((uVar13 != 1) || (local_a038 == (char *)0xffffffff)) {
            printf("SWD swd_flash_write 0x%x\n",0x80);
            perror("write flash");
            uVar12 = 0x19;
            goto LAB_0001195c;
          }
          local_a038 = (char *)0x0;
          ioctl(iVar1,0x40046fd8,&local_a038);
          ioctl(iVar1,0x40046fd9,&local_a038);
          in_stack_ffff4f9c = 0xff;
          in_stack_ffff4f98 = 0xff;
          iVar2 = FUN_00010c0c(iVar1,(uint *)local_9030,0x81,0xff,0xff,0xff,0xff,(undefined4 *)0x0);
 ``` 
 
 If the checks are correct the function FUN_00010c0c is further called to write the spi flash.  

```c
 iVar2 = ioctl(param_1,0x40046fe0,&local_120);
  if (iVar2 == 0) {
    if (-1 < (int)local_11c) {
      puVar8 = &local_120;
      do {
        if (*(char *)puVar8 == -2) {
          uVar1 = crc32(0,0);
          uVar3 = crc32(uVar1,puVar8,8);
          if (uVar3 == puVar8[2]) {
            puVar6 = puVar8;
            do {
              puVar7 = puVar6 + 1;
              *param_2 = *puVar6;
              puVar6 = puVar7;
              param_2 = param_2 + 1;
            } while (puVar7 != puVar8 + 4);
            return 1;
          }
        }
        iVar2 = iVar2 + 1;
        puVar8 = (uint *)((int)puVar8 + 1);
      } while (iVar2 != 0xf8);
    }
  }
  else {
    printf("%s %d\n","spiFlashIoctl",0x37);
  }
  ```
  Once a return value of Not -45 has been returned, a subrotutine will be called to inact the update sequence. 
  
   ``` c
 LAB_0001195c:
  close(iVar1);
  usleep(100000);
  iVar1 = open("/proc/bus/pci/00/00.0",1);
  if (-1 < iVar1) {
    if ((0x13 < local_b054) && (pwrite(iVar1,auStack_b028,4,0), 0x3c < local_b054)) {
      pwrite(iVar1,auStack_affc,1,0);
    }
    close(iVar1);
  }
  printf("poe update finished, res %d\n",uVar12);
  return uVar12;
  ```   
  
  

#### Signature verification 

There is an option for the signatue to be verified for the POE update. It appears that RouterOS has spesific IOCTL calls to ATiny chip for some sort of signature verification. 

Ivar1 is rthe file descriptor
 ``` c 
  local_b03c = pcVar4;
  iVar2 = ioctl(iVar1,0x80046fef);
  if (iVar2 < 0) {
    perror("read tiny signature");
    uVar12 = 0xb;
  }
 ``` 
 ```  c
   else {
    printf("Attiny signature: %x\n",(uint)local_b03c);
    if (local_b03c == (char *)0x1e9208) {
      iVar2 = ioctl(iVar1,0x50086ff0,&local_a038);
      if (iVar2 < 0) {
        uVar12 = 0x19;
        perror("write flash");
      }
   ```     
 Both of the errors are for the ATtiny signature... 
 
 #### What is an ATiny?
 
 An ATtiny chip is a type of microcontroller made by Atmel Corporation . It is a small (Hence the name) and an low cost chip that can be programmed to perform various functions in electronic devices.
 
 In our case it is being used to verify it is the correct device with a unique signature. 
 The signature is a unique identifier that is programmed into the ATtiny microcontroller during the manufacturing process. It is a 3-byte code that represents the device's manufacturer, device family, and device type. The signature is stored in a special read-only memory (ROM) area of the microcontroller, known as the Signature Row.
 
The ATtiny signature is used by programming tools to identify the specific microcontroller that is being programmed, to ensure that the correct firmware is loaded onto the device. It is also used for verification purposes, to ensure that the microcontroller being used in a particular application is genuine and not a counterfeit.
In our case it would be used to verify the POE update is on the correct device with the retun value from the IOCTL. 

This is the lowest I am going to go on this, otherwise it will delive into logic gates on how this chip works.....

### Binary Loading 

Within the internels how are the binaries initialy loaded and configured?

XML of course! (somewhat) This is a unuiqe format for RouterOS, within the file you can see here is is used to load the biniares as a config file this is done on boot and read with  libuxml++.so
### System.x3 
  ``` 
/nova/bin/resolver
/nova/bin/mactel
/nova/bin/undo
/nova/bin/macping
/nova/bin/cerm
/nova/bin/cerm-worker
/nova/bin/net
/nova/bin/fileman
/nova/bin/ping
/nova/bin/sys
/nova/bin/traceroute
...
 ```

### liburadius

/lib/liburadius.so

liburadius.so is a shared library file that provides a set of functions and symbols that can be used by other software programs. In particular, it provides functionality related to the RADIUS (Remote Authentication Dial-In User Service) protocol, which is used for remote authentication and accounting in computer networks.


The libary file is a custom one made by MicroTick, this was indicated by the some of the commands withing the libary file. The call of nv::message I will detail more later. 

The command used in function FUN_00012834:
```c
  nv::message::~message((message *)(param_1 + 4)); //lib/libumsg.so 
 ```

Start --> End 

#### FUN_000127dc: 

Sets the "basefield" flag of the ios object to std::ios_base::binary (i.e., sets the output formatting to binary).

 ```c
  ios::setf(param_1,2);
  return param_1;
}
 ``` 

### FUN_000127f8:

Deletes the element pointed to by the pointer *param_1 from a vector_base object pointed to by param_1, then calls the destructor for that vector_base object.

 ```c
{
  vector_base::erase_raw((char *)param_1,*param_1);
  vector_base::~vector_base((vector_base *)param_1);
  return param_1;
}
```


#### FUN_00012878:
Allocates memory for a new array of size 20 (presumably to store a nv::message object and some additional data), then initializes the first four elements of the array with &PTR_LAB_00025ec0, the contents of two specific addresses in the input param_1 array, and the contents of two specific addresses immediately following those in the param_1 array. Finally, it initializes the remaining elements of the new array with a nv::message object constructed from data in the input param_1 array, then returns a pointer to the new array.

 ```c
  puVar1 = (undefined4 *)malloc(0x14);
  *puVar1 = &PTR_LAB_00025ec0;
  puVar1[1] = *(undefined4 *)(param_1 + 4);
  uVar2 = *(undefined4 *)(param_1 + 0xc);
  puVar1[2] = *(undefined4 *)(param_1 + 8);
  puVar1[3] = uVar2;
  nv::message::message((message *)(puVar1 + 4),(message *)(param_1 + 0x10));
  return puVar1;
 ```

### FUN_000128c8:
Writes a hexadecimal representation of the param_3 bytes starting at the address param_2 to the output stream param_1, with some additional formatting.
 ```c
   iStack_24 = param_2;
  operator<<(param_1,"0x");
  for (uVar1 = 0; uVar1 != param_3; uVar1 = uVar1 + 1) {
    if ((uVar1 != 0) && ((uVar1 & 0xf) == 0)) {
      endl(param_1);
      operator<<(param_1,"      ");
    }
    snprintf((char *)&iStack_24,3,"%2.2x",(uint)*(byte *)(param_2 + uVar1));
    operator<<(param_1,(char *)&iStack_24);
  }
  ```
  
### FUN_000129b0: 
This function takes in two parameters, a pointer to an integer and a pointer to an unsigned integer. It first checks if the least significant byte of the unsigned integer is not zero, and if so, it prints a formatted string to the output stream pointed to by the integer pointer. Then it calls another function with a modified integer pointer to perform some other task. Finally, it prints the remaining three bytes of the unsigned integer to the output stream.

 ```c
   if ((uVar2 & 0xff) != 0) {
    poVar1 = (ostream *)operator<<((ostream *)param_1,"(");
    poVar1 = (ostream *)operator<<(poVar1,uVar2 & 0xff);
    operator<<(poVar1,") ");
  }
  FUN_000127dc((int)param_1 + *(int *)(*param_1 + -0xc));
  operator<<((ostream *)param_1,
             (uVar2 >> 8 & 0xff) << 0x10 | (uVar2 >> 0x10 & 0xff) << 8 | uVar2 >> 0x18);
             return; 
  ```

### FUN_00012a84
This function takes in two parameters, a pointer to an integer and an unsigned integer. It first calculates the size of a memory buffer by subtracting the integer pointed to by the second parameter from the integer pointed to by the first parameter. If the second parameter is less than the buffer size, it deletes some data from the buffer using the vector_base::erase_raw function. If the second parameter is greater than the buffer size, it adds some data to the buffer using the vector_base::insert_raw function.

```c
  if (param_2 < uVar1) {
    vector_base::erase_raw((char *)param_1,(char *)(*param_1 + param_2));
    return;
  }
  uVar1 = param_2 - uVar1;
  if (uVar1 == 0) {
    return;
  }
  __s = (void *)vector_base::insert_raw((char *)param_1,param_1[1],uVar1);
  memset(__s,0,uVar1);
```

### FUN_00012be0: 

This function takes an ostream object, a pointer to a byte array (byte *), and a uint parameter. It loops through the byte array and checks if each byte is in the range [0x20, 0x7e]. If all bytes are in this range, it converts the byte array to a string, encloses it in double quotes, 
```c
  do {
    local_14 = param_2;
    if (pbVar3 == param_2 + param_3) {
      poVar2 = (ostream *)operator<<(param_1,'\"');
      string::string((string *)&local_14,(char *)param_2,param_3);
      poVar2 = (ostream *)FUN_00012bc4(poVar2,(char)local_14);
      operator<<(poVar2,'\"');
      string::freeptr();
      return;
    }
    bVar1 = *pbVar3;
    pbVar3 = pbVar3 + 1;
  } while (bVar1 - 0x20 < 0x5f);
```

### FUN_00012c64: 
This function takes an ostream object, a pointer to a byte array, and a uint parameter. If the first byte of the byte array is less than 0x20, it writes the byte enclosed in parentheses to the ostream. Then, it calls FUN_00012be0 with the same parameters.

```c
  if ((param_3 != 0) && (uVar2 = (uint)*param_2, uVar2 < 0x20)) {
    param_2 = param_2 + 1;
    param_3 = param_3 - 1;
    if (uVar2 != 0) {
      poVar1 = (ostream *)operator<<(param_1,"(");
      poVar1 = (ostream *)operator<<(poVar1,uVar2);
      operator<<(poVar1,") ");
    }
  }
  FUN_00012be0(param_1,param_2,param_3);
 ``` 

### FUN_00012cdc
This function takes an ostream object and a pointer to an undefined 4-byte array (undefined4 *). It calls FUN_00012a3c with auStack_20 and param_2 as parameters, which is not shown here. It then calls IPAddr6::str to convert the auStack_20 array to a string representation of an IPv6 address, stores the result in local_24, and writes local_24 to the ostream.

 ```c
  IPAddr6::str((bool)((char)&stack0xfffffff4 + -0x18));
  FUN_00012bc4(param_1,local_24);
  string::freeptr();
  return;
   ``` 
 
###  FUN_00012d98

 Function takes two parameters: param_1, which is a pointer to a pointer to an integer, and param_2, which is a pointer to an integer. The function first checks if the integer pointed to by the pointer to the pointer param_1 is equal to the integer pointed to by param_2. If they are equal, the function calls the string::compare function with SUB41(param_1,0) as its argument. This is a bit convoluted, but essentially SUB41(param_1,0) just dereferences the pointer to the pointer param_1 to get a pointer to an integer, which is then implicitly converted to a string object.

The string::compare function compares the string represented by its this pointer (which is the string object that was implicitly created) with the string represented by its argument. The return value is an integer that is negative if the first string is less than the second, zero if they are equal, or positive if the first string is greater than the second.

The  count_leading_zeroes function takes an unsigned integer as its argument and returns the number of leading zeroes in its binary representation.

Finally, the function right-shifts the result of  ```count_leading_zeroes(string::compare(...)) ```  by 5 (i.e. divides by 32) and returns the result.

This function could potentially be vulnerable to a type confusion vulnerability. The fact that it takes a pointer to a pointer to an integer and implicitly converts it to a string object could be problematic if an attacker is able to pass a pointer to an object that is not actually an integer, but instead contains a malicious object that can exploit the string::compare function or cause some other type of undefined behavior. Additionally, the count_leading_zeroes function could potentially be exploited if an attacker can pass an argument that causes an integer overflow. 


   ```c 
   uint uVar1;
  undefined4 uVar2;
  
  if (**param_1 == *param_2) {
    uVar2 = string::compare(SUB41(param_1,0));
    uVar1 = count_leading_zeroes(uVar2);
    uVar1 = uVar1 >> 5;
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
   ``` 
 
 
   
   #### In Sumary 
      
In summary, the code provided is a C++ library for handling IP addresses. It includes functions for parsing and formatting IPv4 and IPv6 addresses, as well as converting between different representations of IP addresses.

The library is composed of several functions, including FUN_000127dc which checks the validity of an IPv6 address and returns a boolean value indicating whether it is valid or not. There are also functions such as FUN_00012be0 which formats an IP address as a string and FUN_00012cdc which converts an IPv6 address to a string.

One potentially vulnerable function is FUN_00012d98, which compares two IP addresses and returns a value indicating the number of leading zeroes in their binary representation. This function could potentially be exploited if input validation is not performed properly, leading to a buffer overflow or other security vulnerabilities.

Overall, the library provides useful functionality for working with IP addresses, but it is important to ensure that proper input validation and error handling is implemented to prevent potential security vulnerabilities.


### Example POC 

Here is a somewhat example of a possible bug in the code, this probably cant be teiggered from outside the code base but in an ideal world it can! After a few hours of revising c++, Alas! 

```c++
  #include <iostream>
#include <bitset>
#include <cstring>

// Counts the number of leading zero bits in a 32-bit integer.
uint32_t count_leading_zeroes(uint32_t value) {
    // Use bitset to count leading zeros.
    std::bitset<32> bits(value);
    return (bits._Find_first() == 32) ? 32 : bits._Find_first();
}

// The vulnerable function that uses count_leading_zeroes().
uint32_t FUN_00012d98(int **param_1, int *param_2) {
    uint32_t uVar1;
    uint32_t uVar2;

    // If the value at the address of the value at param_1 is equal to the value at param_2.
    if (**param_1 == *param_2) {
        // Get the length of the string pointed to by the value at param_1.
        uVar2 = strlen((char *)*param_1);

        // Count the number of leading zeroes in the length as a hex string.
        uVar1 = count_leading_zeroes(uVar2);
        uVar1 = uVar1 >> 5;
    }
    else {
        // Set the result to 0 if the values are not equal.
        uVar1 = 0;
    }

    return uVar1;
}

// The main function that triggers the vulnerability.
int main() {
    int x = 0x12345678;
    int *p1 = &x;
    int *p2 = &x;

    // Call the vulnerable function with the pointers.
    uint32_t result = FUN_00012d98(&p1, p2);

    if (result == 0) {
        // The vulnerability is not triggered.
        std::cerr << "Memory error: the vulnerability is not triggered\n";
    }
    else {
        // The vulnerability is triggered.
        std::cout << "The vulnerability is triggered with result: " << result << "\n";
    }

    return 0;
}
```

```bash

$ g++ poc.cpp -fsanitize=address -static-libasan -g

$ ./poc


==3898500==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fffb469c6a4 at pc 0x56086a885fb1 bp 0x7fffb469c620 sp 0x7fffb469bdd0
READ of size 5 at 0x7fffb469c6a4 thread T0                                                                                                                                                                                                  
    #0 0x56086a885fb0 in __interceptor_strlen.part.0 (/home/kali/test_tick/a.out+0x2efb0)
    #1 0x56086a93c01e in FUN_00012d98(int**, int*) /home/kali/test_tick/poc.cpp:20
    #2 0x56086a93c13e in main /home/kali/test_tick/poc.cpp:41
    #3 0x7fe2cd167189 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #4 0x7fe2cd167244 in __libc_start_main_impl ../csu/libc-start.c:381
    #5 0x56086a8603a0 in _start (/home/kali/test_tick/a.out+0x93a0)

Address 0x7fffb469c6a4 is located in stack of thread T0 at offset 52 in frame
    #0 0x56086a93c050 in main /home/kali/test_tick/poc.cpp:35

  This frame has 2 object(s):
    [48, 52) 'x' (line 36) <== Memory access at offset 52 overflows this variable
    [64, 72) 'p1' (line 37)
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow (/home/kali/test_tick/a.out+0x2efb0) in __interceptor_strlen.part.0
Shadow bytes around the buggy address:
  0x1000768cb880: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x1000768cb890: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x1000768cb8a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x1000768cb8b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x1000768cb8c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 f1 f1
=>0x1000768cb8d0: f1 f1 f1 f1[04]f2 00 f3 f3 f3 00 00 00 00 00 00
  0x1000768cb8e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x1000768cb8f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x1000768cb900: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x1000768cb910: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x1000768cb920: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==3898500==ABORTING
```


Alas! The final part I will be reversing to finish this litte project!

## libumsg 
This libary its self would constitute a full write up for as it is huge and an integral part of MicroTicks internels. 



###  nv::kernelGetMacAddr

This is a C++ function named nv::kernelSocket() which returns an integer. The purpose of this function is to create a kernel socket if it does not already exist and return the socket descriptor.

```c
int nv::kernelSocket(void)

{
  if (DAT_00069c08 == -1) {
    DAT_00069c08 = socket(2,2,0);
  }
  return DAT_00069c08;
}
```

### nv::kernelGetMacAddr 

 kernelSocket and ioctl functions to retrieve the MAC address associated with a network interface, which is stored in an nv object. If the ioctl call fails, an error message is printed to cout and the nv object is zeroed out. The security of this function depends on its integration with the rest of the software system.
 

```c
nv * __thiscall nv::kernelGetMacAddr(nv *this,string *param_1)

{
  int iVar1;
  int *piVar2;
  undefined4 uVar3;
  nv *pnVar4;
  byte bVar5;
  int local_40;
  char local_3c [18];
  undefined4 local_2a [6];
  
  bVar5 = 0;
  strncpy(local_3c,(char *)(*(int *)param_1 + 4),0x10);
  iVar1 = kernelSocket();
  iVar1 = ioctl(iVar1,0x8927,local_3c);
  if (iVar1 == -1) {
    piVar2 = __errno_location();
    ioctlErrorStr((nv *)&local_40,param_1,"SIOCGIFHWADDR",*piVar2);
    uVar3 = FUN_0003995d((ostream *)&cout,&local_40);
    FUN_0002da9e(uVar3,endl);
    string::freeptr();
    pnVar4 = this;
    for (iVar1 = 6; iVar1 != 0; iVar1 = iVar1 + -1) {
      *pnVar4 = (nv)0x0;
      pnVar4 = pnVar4 + (uint)bVar5 * -2 + 1;
    }
  }
  else {
    FUN_0005cbb0((undefined4 *)this,local_2a);
  }
  return this;
}

```

### nv::message::extract<nv::bool_id>
 It is a templated function that takes a pointer to a message object, a bool_id object, and a pointer to a type object as its parameters.

The purpose of this function is to extract a boolean value from the message object and store it in the type object pointed to by param_2. The bool_id parameter specifies which boolean value to extract.


```c 
void __thiscall nv::message::extract<nv::bool_id>(message *this,bool_id param_1,type *param_2)

{
  bool bVar1;
  set_type sVar2;
  
  bVar1 = has<nv::bool_id>(this,param_1);
  if (bVar1) {
    sVar2 = get<nv::bool_id>(this,param_1);
    *param_2 = SUB41(sVar2,0);
  }
  return;
}
```


 nv::message::ref<IPAddr6>
      
      
addr nv::StoreCord::getEntry
      
      
addr nv::Handler::findListenersFor
      
      
addr nv::follow
      
      
addr nv::Logger::Logger
      
      
addr nv::RemoteObject::~RemoteObject
      
      
addr nv::ThinRunner::addBeforeSleep
      
      
addr nv::ThinRunner::addTimer
      
      
addr nv::ThinRunner::changeSocket
      
      
addr nv::Allocator::free
      
      
addr nv::ArpResolver::send
      
addr nv::Allocator::allocate
      
      
addr nv::ThinRunner::removeTimer
      
      
addr nv::Allocator::allocate
      
      
addr nv::Handler::handleCmd
      
      
addr nv::followHandlerIdRange
      
      
addr nv::AMapMirror::cleanup
      




### References:

Kirils Solovjovs. (2017). Tools for effortless reverse engineering of MikroTik routers. [Online]. NA. Available at: https://kirils.org/slides/2017-09-15_prez_15_MT_Balccon_pub.pdf [Accessed 31 March 2023].

ATtiny. (2013). Atmel 8-bit AVR Microcontroller with 2/4/8K Bytes In-System Programmable Flash. [Online]. ATtiny25. Available at: https://ww1.microchip.com/downloads/en/DeviceDoc/Atmel-2586-AVR-8-bit-Microcontroller-ATtiny25-ATtiny45-ATtiny85_Datashe [Accessed 31 March 2023].

NA. (2010). what_is_routeros.pdf. [Online]. NA. Available at: https://i.mt.lv/files/pdf/instructions/what_is_routeros.pdf [Accessed 31 March 2023].
