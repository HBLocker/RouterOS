### MicroTick at a glance 

### DRAFT 1.0  Basic intro, overview of SWUPD AND devel login. 
!subject to change. 

Microtick at a Glance. 


I was looking at Shodan and was more looking at open devices and stumbled across Microtick routers. Which began this rabbit hole I gradually fell down….

![Router os open devices world wide ](https://www.shodan.io/search/facet.png?query=mikrotik&facet=country)


## RouterOS 

In RouterOS, the Linux kernel provides a stable and reliable foundation for managing network infrastructure. It is highly optimized for networking and supports a wide range of hardware, including network adapters, wireless cards, and routers. Additionally, RouterOS includes a range of networking services and features built on top of the Linux kernel, such as routing, firewall, NAT, wireless access point, hotspot, VPN, and more. 

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

 ### The poeupdatefwv3 
   
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



 ### Main update function -  FUN_000115ac  
  
  
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
 ## Writing to memory 
 
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
  
  




