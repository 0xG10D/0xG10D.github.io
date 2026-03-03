---
description: >-
  Deploy the machine attached to this task; once it is ready, it will be visible
  in the split-screen view. If you don't see a virtual machine load, click the
  Show Split View button.
---

# 🐽 Interactive Material & VM

### Interactive material and exercise setup

Once the machine has fully started, you will see a folder named "**Task-Exercises**" on the Desktop. Each exercise has an individual folder and files; use them accordingly to the questions.

Everything you need is located under the "**Task-Exercises**" folder.

There are two sub-folders available:

* `Config-Sample`: Sample configuration and rule files. These files are provided to show what the configuration files look like. Installed Snort instance doesn't use them, so feel free to practice and modify them. Snort's original base files are located under **`/etc/snort`** folder.
* `Exercise-Files`: There are separate folders for each task. Each folder contains pcap, log, and rule files ready to play with.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/56e7b4aff9791dd79f280b9e18350499.png)

### Traffic Generator

The machine is offline, but there is a script `traffic-generator.sh` for you to generate traffic to your Snort interface. You will use this script to trigger traffic to the Snort interface. Once you run the script, it will ask you to choose the exercise type and then automatically open another terminal to show you the output of the selected action.

**Note that each traffic flow is designed for a specific exercise. Make sure you start the Snort instance and wait until the end of the script execution. Don't stop the traffic flow unless you choose the wrong exercise.**&#x20;

Run the "traffic generator.sh" file by executing it as sudo.&#x20;

executing the traffic generator script

```shell-session
user@ubuntu$ sudo ./traffic-generator.sh 
```

General desktop overview. Traffic generator script in action.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/a1f0fbcda5c475ae78da0dbd96267892.png)

Once you choose an action, the menu disappears, and a terminal instance opens to show you its output.&#x20;

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/5550256e1a64efe83b33535f84147ec4.png)

Answer the questions belowNavigate to the Task-Exercises folder and run the command "./.easy.sh" and write the output.

Answer:

```
Too Easy!
```
