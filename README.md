# Android Bulletins Harvester

The simple utility for parsing Android security bulletins. The utility automatically scans bulletins and provides the user with detailed information about a closed vulnerability, including its type, severity, and patch. The utility also allows to configure filters and output type

# Usage
```
~$ git clone https://github.com/dukebarman/android-bulletins-harvester
~$ cd android-bulletins-harvester
~/android-bulletins-harvester$ go build .
```

# Help

```
Usage of android-bulletin-harvester.go:
  -android string
        Filter CVEs by Android version
  -json
        Output in json format
  -output string
        File name for output json
  -unpublish
        Show unpublished CVE
  -url string
        Parse needed Security Bulletin or last or all from https://source.android.com (default "last")
```

# Examples

* Default format

```
~/android-bulletins-harvester$ ./android-bulletins-harvester
# https://source.android.com/docs/security/bulletin/2023-06-01

* CVE-2023-21127 (RCE, Critical): [Patch](https://android.googlesource.com/platform/frameworks/av/+/ff06107de18166f1d97baddabfe23a608ef35ceb)
Android affected versions: 11,12,12L,13
* CVE-2023-21126 (EoP, High): [Patch](https://android.googlesource.com/platform/frameworks/base/+/b8e6044520761f537473d0a04a651118236d2c52) [Patch](https://android.googlesource.com/platform/frameworks/base/+/0f857518e3dd6490508a88ceac39309e77cb231b) [Patch](https://android.googlesource.com/platform/frameworks/base/+/3721a8ad742248e7c017115c088291015f40319d)
Android affected versions: 13
...
```

* JSON format

```
~/android-bulletins-harvester$ ./android-bulletins-harvester -json -output cves.json
~/android-bulletins-harvester$ cat cves.json # after magic beatify 
...
            },
            {
                "CveID": "CVE-2023-21137",
                "PatchLinks": [
                    "https://android.googlesource.com/platform/frameworks/base/+/f11ce5d7cac6a128d3eefad2b8e94ca7dd054713"
                ],
                "CveType": "DoS",
                "CveSeverity": "High",
                "AVersion": [
                    "11",
                    "12",
                    "12L",
                    "13"
                ]
            },
            {
...
```