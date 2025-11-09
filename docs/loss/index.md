---
title: Disk Forensics: Image Analysis
tags: [Forensics, OSINT, CTF]
description: An introduction to disk imaging, file carving, and timeline analysis in digital forensics.
date: 2025-09-15
---

## Introduction to Digital Forensics
Digital forensics is a branch of forensic science encompassing the recovery and investigation of material found in digital devices, often in relation to computer crime. Disk forensics focuses specifically on data stored on hard drives, SSDs, and other storage media.

The primary goal is to identify, preserve, analyze, and present digital evidence in a legally admissible format.

### Disk Imaging
The first and most critical step in disk forensics is **imaging** the suspect drive. This involves creating a bit-for-bit copy of the entire storage device, including free space, slack space, and unallocated clusters. This ensures that the original evidence remains untouched and maintains its integrity.

Common imaging tools:
*   `dd` (Linux command-line)
*   FTK Imager (Windows)
*   EnCase Forensic

```bash
# Example using dd to create a disk image
sudo dd if=/dev/sdb of=/media/forensics/evidence.img bs=4M conv=noerror,sync