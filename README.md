# findRogueAP

First of all, execute the following commands on Cisco WLC, save the results in a `.txt` or `.log` file.

```
config paging disable
show advanced 802.11a summary
show rogue ap summary
```



Secondly, you need a DNA Center and access the Rogue Management Dashboard. If you are using DNAC 1.x.x, explore to **ASSURANCE > Dashboards > Rogue Management > Threats**. Sort by RSSI through clicking on "RSSI", copy the contents to a `.csv` or `.xls` file without the header. 

**Do NOT modify the columns.** 

![DNAC_Treats_version1](https://github.com/chenghit/findRogueAP/blob/main/DNAC_Treats_version1.jpg)



If you are using DNAC 2.x.x, explore to **Assurance > Rogue and aWIPS > Threats**. You can see the columns are different from the ones on DNAC 1.x.x. Sort by RSSI through clicking on "RSSI", copy the contents to a `.csv` or `.xls` file without the header. 

**Again, do NOT modify the columns.** 

![DNAC_Treats_version2](https://github.com/chenghit/findRogueAP/blob/main/DNAC_Treats_version2.jpg)



After install the requirements, run `main.py`:

```
$ python main.py --help                                                                                                                                   
Usage: main.py [OPTIONS]
Options:
  --txt TEXT         txt或者log文件路径，包含WLC "show advanced 802.11a summary"和"show
                     rogue ap summary"结果。File path of a .txt or .log file
                     which includes the results of "show advanced 802.11a
                     summary" and "show rogue ap summary".

  --table TEXT       csv或者xls文件路径，DNAC RogueManagement
                     Dashboard报表，默认Columns复制即可，请勿自定义列。File path of a .csv or
                     .xls file which includes the contents copied from
                     RogueManagement Dashboard on DNAC. Do NOT modify columns
                     on DNAC!

  --version INTEGER  DNAC main version number. 1 or 2. Default is 1.
  --help             Show this message and exit.

```



