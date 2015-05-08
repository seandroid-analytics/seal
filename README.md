## SEAL: SEAndroid Analytics Library for live device analysis

[SEAL](https://github.com/seandroid-analytics/seal/wiki) is a SEAndroid live device analysis tool. It can perform policy analysis on Android devices (real or emulated) connected through ADB.
```
usage: seal [-h] [--adb ADB] [--device <DEVICE>]
               {polinfo,files,processes} ...

positional arguments:
  {polinfo,files,processes}
                        sub-command help
    polinfo             Show policy info from device
    files               List all files on the device
    processes           List all processes on the device

optional arguments:
  -h, --help            show this help message and exit
  --adb ADB             Path to your local root adb if not in your $PATH
  --device <DEVICE>     Specify a device to work with
```

The tool offers functionality through a set of subcommands. The current ones are:

* [polinfo](https://github.com/seandroid-analytics/seal/wiki#polinfo) - view policy statistics from a connected device
* [files](https://github.com/seandroid-analytics/seal/wiki#files) - list files on the device, optionally filtering to show only files a specific process has access to
* [processes](https://github.com/seandroid-analytics/seal/wiki#processes) - list processes on the device, optionally filtering to show only processes that have access to a specific file/path

A graphical frontend to the SEAL library is available as [SEALX](https://github.com/seandroid-analytics/seal/wiki/SEALX).

## Obtaining SEAL
The SEAL library may be obtained by cloning this repository. From the command line, do:

```$ git clone git@github.com:seandroid-analytics/seal.git```

The SEAL library requires the Python bindings to libapol and libqpol from [SEToolsv3](https://github.com/TresysTechnology/setools).
These can be obtained on Ubuntu 14.04 LTS by installing the `python-setools` package.

## Running SEAL
From the resulting directory, run:

```$ python seal/seal.py [GLOBAL OPTIONS] <subcommand> [OPTIONS]```

To run the graphical version:

```$ python seal/sealx.py```

## Reporting bugs
You can report bugs in the project [issue tracker](https://github.com/seandroid-analytics/seal/issues).

## License
Copyright 2015 Filippo Bonazzi

SEAL is licensed under the Apache License 2.0 (see LICENSE)
