# Optional PawnIO temperature modules

Unmodified signed IntelMSR.bin, IntelMCHBAR.bin and AMDFamily17.bin from the official PawnIO.Modules 0.2.11 release:
https://github.com/namazso/PawnIO.Modules/releases/tag/0.2.11

Copyright namazso and Gen Li, LGPL-2.1-or-later. Full license: COPYING. Corresponding upstream source archive: PawnIO-Modules-0.2.11-source.zip. Upstream build dependencies and module API are described in that source tree. The modules can be replaced using SensorModules/IntelMSR.bin and SensorModules/IntelMCHBAR.bin next to the application, but only in a protected administrator-owned Program Files installation; the installed official PawnIO driver enforces its own module signature checks. PC Sentinel's complete application source is provided in the accompanying source package.

IntelMSR.bin SHA256: D6ED85D65AB17A22F813EF98207D6D537155EE2DED5976A21CB48413C9B92E5F
IntelMCHBAR.bin SHA256: 3F82B832D99B4AAC37D2A20FDB7C9BAA2A3BC0488612C9019C9484EB0E8A6EAE

These are interpreter modules, not a kernel driver or an installer. PC Sentinel never installs/starts a driver or elevates itself. Modules are used only with an already installed PawnIO driver. This client calls only ioctl_read_msr (0x1A2 / 0x1B1) and ioctl_read_dword (0x59C0, supported Raptor Lake models only). It does not provide control-write functions.

AMDFamily17.bin SHA256: DAE74615761B78BDF064DFB3E136252DDCC6FC727D88F14738D0E5800D427A91
AMD temperature uses ioctl_read_smn only for 0x59800 under Global\\Access_PCI mutex. SMN reading selects the PCI index register before reading the data register; no frequency, power or fan control register is changed. Tctl is explicitly labelled, not substituted for Tdie.
