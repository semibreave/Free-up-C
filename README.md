# Free-up-C
 
## Table of contents
* [General info](#general-info)
* [Technologies](#technologies)
* [Setup](#setup)

## General info
This project is written in PowerShell to assist the System Admins to clean up boot drive for Windows patching.
1. Script will check on the Windows OS version and the C free space available.
2. If the OS version and the amount of free space complied with each other,script will not do anything further but logging.
3. If the above doesn't complied, script will proceed to clean up the predefined path which was pre determined not affecting the OS and also applications.
4. Upon cleaned up, script will again check for compliancy.
5. If above doesnt yet to yield compliancy, script will report how much more space required for compliancy. Proceed to logging.
6. Logging is saved as csv format.
	
## Technologies
Project is created with:
* PowerShell 5.1
* Access to WMI Objects
* Access to Active Directory Objects
	
## Setup
1. Run the script on a reliable jump machine with well defined DNS suffixes.
2. Create a text file and named it as 'computers.txt' on the desktop.
3. Paste the computer name line by line in the above text file.
4. Run the script with either ISE or PowerShell console.
