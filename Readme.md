### MicroTick at a glance 
!subject to change. 

Microtick at a Glance. 


I was looking at Shodan and was more looking at open devices and stumbled across Microtick routers. Which began this rabbit hole I gradually fell down….

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



### References:

Kirils Solovjovs. (2017). Tools for effortless reverse engineering of MikroTik routers. [Online]. NA. Available at: https://kirils.org/slides/2017-09-15_prez_15_MT_Balccon_pub.pdf [Accessed 31 March 2023].

ATtiny. (2013). Atmel 8-bit AVR Microcontroller with 2/4/8K Bytes In-System Programmable Flash. [Online]. ATtiny25. Available at: https://ww1.microchip.com/downloads/en/DeviceDoc/Atmel-2586-AVR-8-bit-Microcontroller-ATtiny25-ATtiny45-ATtiny85_Datashe [Accessed 31 March 2023].


NA. (2010). what_is_routeros.pdf. [Online]. NA. Available at: https://i.mt.lv/files/pdf/instructions/what_is_routeros.pdf [Accessed 31 March 2023].






